"""
Tests for P3 MCP broker gateway integration.

Covers:
  - _bridge.py: request/response correlation, notification→202 no-block,
    crash-restart, JWT never logged (Laura SB-1)
  - registry.py: McpBrokerRegistry, build_registry_from_env
  - mcp_router_runtime.py: tools/call gated, session passthrough, deny→403,
    unknown agent→404, XFF header stripping, posture invariant
  - _jwks.py: JWKS Cache-Control max-age fix (Nico)
  - _jwt.py: FIPS provider assertion (Nico)

v2.25.0 / P3 gateway integration.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import unittest.mock as mock
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonrpc_request(method: str, params=None, req_id="1") -> str:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _make_jsonrpc_notification(method: str, params=None) -> str:
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _make_jsonrpc_response(req_id, result=None) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result or {}})


# ---------------------------------------------------------------------------
# _bridge.py tests
# ---------------------------------------------------------------------------

class TestBridgeProtocol:
    """Test the _BridgeProcess request/notification distinction."""

    def test_is_notification_when_no_id(self):
        """A message without 'id' is a notification."""
        msg = json.loads(_make_jsonrpc_notification("notifications/initialized"))
        assert "id" not in msg

    def test_is_request_when_has_id(self):
        """A message with 'id' is a request."""
        msg = json.loads(_make_jsonrpc_request("tools/call", req_id="abc123"))
        assert "id" in msg
        assert msg["id"] == "abc123"

    @pytest.mark.asyncio
    async def test_send_notification_does_not_block_for_response(self):
        """
        Sending a notification must return without waiting for any response.
        This is the protocol correctness crux — a blocking read after a
        notification would deadlock the session.
        """
        from yashigani.mcp._bridge import _BridgeProcess

        bridge = _BridgeProcess(
            command=[sys.executable, "-c",
                "import sys\n"
                "for line in sys.stdin:\n"
                "    line = line.strip()\n"
                "    if not line: continue\n"
                "    import json\n"
                "    msg = json.loads(line)\n"
                "    # Never respond to notifications (no 'id')\n"
                "    if 'id' in msg:\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{}}))\n"
                "        sys.stdout.flush()\n"
            ],
        )
        await bridge.start()
        try:
            # Notification — must return quickly (no response expected)
            notif = _make_jsonrpc_notification("notifications/initialized")
            await asyncio.wait_for(bridge.send_notification(notif), timeout=2.0)
            # No exception + no timeout = correct
        finally:
            await bridge.stop()

    @pytest.mark.asyncio
    async def test_send_request_returns_correlated_response(self):
        """
        Sending a request with id='test-42' must return the response with
        matching id.
        """
        from yashigani.mcp._bridge import _BridgeProcess

        bridge = _BridgeProcess(
            command=[sys.executable, "-c",
                "import sys, json\n"
                "for line in sys.stdin:\n"
                "    line = line.strip()\n"
                "    if not line: continue\n"
                "    msg = json.loads(line)\n"
                "    if 'id' in msg:\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'ok':True}}))\n"
                "        sys.stdout.flush()\n"
            ],
        )
        await bridge.start()
        try:
            req = _make_jsonrpc_request("tools/call", {"name": "read_file"}, req_id="test-42")
            response_str = await asyncio.wait_for(bridge.send_request(req), timeout=5.0)
            response = json.loads(response_str)
            assert response["id"] == "test-42"
            assert response["result"]["ok"] is True
        finally:
            await bridge.stop()

    @pytest.mark.asyncio
    async def test_crash_restart(self):
        """
        If the subprocess crashes, send_request should restart it and succeed.
        """
        from yashigani.mcp._bridge import _BridgeProcess

        # Process that crashes after the first write
        bridge = _BridgeProcess(
            command=[sys.executable, "-c",
                "import sys, json\n"
                "for line in sys.stdin:\n"
                "    line = line.strip()\n"
                "    if not line: continue\n"
                "    msg = json.loads(line)\n"
                "    print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{}}))\n"
                "    sys.stdout.flush()\n"
                "    sys.exit(0)  # crash after first response\n"
            ],
            restart_on_crash=True,
        )
        await bridge.start()
        try:
            # First request — succeeds
            req1 = _make_jsonrpc_request("tools/list", req_id="r1")
            resp1 = await asyncio.wait_for(bridge.send_request(req1), timeout=5.0)
            assert json.loads(resp1)["id"] == "r1"

            # Wait for subprocess to crash
            await asyncio.sleep(0.2)

            # Second request — bridge should restart subprocess
            req2 = _make_jsonrpc_request("tools/call", req_id="r2")
            resp2 = await asyncio.wait_for(bridge.send_request(req2), timeout=5.0)
            assert json.loads(resp2)["id"] == "r2"
        finally:
            await bridge.stop()

    def test_jwt_never_logged_in_bridge(self, caplog):
        """
        Laura SB-1: The Authorization header value (JWT) must never appear in
        bridge log output.  This test sends a request with a known JWT value and
        asserts it does not appear in any captured log record.
        """
        from yashigani.mcp._bridge import create_bridge_app

        fake_jwt = "eyJhbGciOiJFUzM4NCJ9.FAKE_JWT_VALUE.signature"

        app = create_bridge_app(
            command=[sys.executable, "-c",
                "import sys, json\n"
                "for line in sys.stdin:\n"
                "    line = line.strip()\n"
                "    if not line: continue\n"
                "    msg = json.loads(line)\n"
                "    if 'id' in msg:\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{}}))\n"
                "        sys.stdout.flush()\n"
            ]
        )

        with caplog.at_level(logging.DEBUG, logger="yashigani.mcp._bridge"):
            client = TestClient(app)
            req = _make_jsonrpc_request("tools/call", {"name": "read_file"}, req_id="jwt-test")
            client.post(
                "/mcp",
                content=req,
                headers={"Authorization": f"Bearer {fake_jwt}"},
            )

        # Assert the JWT value itself never appears in any log record
        all_log_text = " ".join(r.message for r in caplog.records)
        assert fake_jwt not in all_log_text, (
            f"Laura SB-1 VIOLATION: JWT value appeared in bridge log output. "
            f"Found in: {all_log_text!r}"
        )
        # Double-check the raw token string is not in any record
        assert "FAKE_JWT_VALUE" not in all_log_text

    @pytest.mark.asyncio
    async def test_notification_returns_202(self):
        """
        HTTP-level test: POST a notification → expect 202 response code.
        """
        from yashigani.mcp._bridge import create_bridge_app

        app = create_bridge_app(
            command=[sys.executable, "-c",
                "import sys, json\n"
                "for line in sys.stdin:\n"
                "    pass\n"
            ]
        )
        client = TestClient(app)
        notif = _make_jsonrpc_notification("notifications/initialized")
        resp = client.post("/mcp", content=notif)
        assert resp.status_code == 202
        assert resp.content == b""

    @pytest.mark.asyncio
    async def test_request_returns_200_with_json_response(self):
        """POST a request → expect 200 with upstream JSON-RPC response."""
        from yashigani.mcp._bridge import create_bridge_app

        app = create_bridge_app(
            command=[sys.executable, "-c",
                "import sys, json\n"
                "for line in sys.stdin:\n"
                "    line = line.strip()\n"
                "    if not line: continue\n"
                "    msg = json.loads(line)\n"
                "    if 'id' in msg:\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'content':'hello'}}))\n"
                "        sys.stdout.flush()\n"
            ]
        )
        client = TestClient(app)
        req = _make_jsonrpc_request("tools/call", req_id="http-1")
        resp = client.post("/mcp", content=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "http-1"
        assert data["result"]["content"] == "hello"

    def test_root_alias_also_works(self):
        """POST to / is an alias for /mcp."""
        from yashigani.mcp._bridge import create_bridge_app

        app = create_bridge_app(
            command=[sys.executable, "-c",
                "import sys, json\n"
                "for line in sys.stdin:\n"
                "    line = line.strip()\n"
                "    if not line: continue\n"
                "    msg = json.loads(line)\n"
                "    if 'id' in msg:\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{}}))\n"
                "        sys.stdout.flush()\n"
            ]
        )
        client = TestClient(app)
        req = _make_jsonrpc_request("initialize", req_id="root-1")
        resp = client.post("/", content=req)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# registry.py tests
# ---------------------------------------------------------------------------

class TestMcpBrokerRegistry:
    """Tests for McpBrokerRegistry and build_registry_from_env."""

    def test_register_and_get(self):
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

        reg = McpBrokerRegistry()
        mock_broker = object()
        cfg = McpBrokerServerConfig(
            upstream_url="http://fs-mcp:8000",
            is_filesystem_agent=True,
            tenant_id="acme",
            agent_name="filesystem-mcp",
        )
        reg.register("filesystem-mcp", mock_broker, cfg)
        result = reg.get("filesystem-mcp")
        assert result is not None
        broker, server_cfg = result
        assert broker is mock_broker
        assert server_cfg.upstream_url == "http://fs-mcp:8000"
        assert server_cfg.is_filesystem_agent is True

    def test_get_unknown_returns_none(self):
        from yashigani.mcp.registry import McpBrokerRegistry

        reg = McpBrokerRegistry()
        assert reg.get("nonexistent-agent") is None

    def test_all_brokers(self):
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

        reg = McpBrokerRegistry()
        b1, b2 = object(), object()
        cfg1 = McpBrokerServerConfig("http://a:8000", False, "t1", "a")
        cfg2 = McpBrokerServerConfig("http://b:8000", True, "t1", "b")
        reg.register("a", b1, cfg1)
        reg.register("b", b2, cfg2)
        brokers = reg.all_brokers()
        assert set(brokers) == {b1, b2}

    def test_build_registry_empty_env(self, monkeypatch):
        """When YASHIGANI_MCP_SERVERS is unset, registry is empty and store is None."""
        monkeypatch.delenv("YASHIGANI_MCP_SERVERS", raising=False)
        from yashigani.mcp.registry import build_registry_from_env
        reg, store = build_registry_from_env(opa_url="http://policy:8181")
        assert len(reg) == 0
        assert store is None

    def test_build_registry_empty_array(self, monkeypatch):
        """Empty JSON array → empty registry."""
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "[]")
        from yashigani.mcp.registry import build_registry_from_env
        reg, store = build_registry_from_env(opa_url="http://policy:8181")
        assert len(reg) == 0
        assert store is None

    def test_build_registry_invalid_json(self, monkeypatch):
        """Invalid JSON → RuntimeError at startup."""
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "not-json{{{")
        from yashigani.mcp.registry import build_registry_from_env
        with pytest.raises(RuntimeError, match="not valid JSON"):
            build_registry_from_env(opa_url="http://policy:8181")

    def test_build_registry_missing_field(self, monkeypatch):
        """Missing required field → RuntimeError."""
        entry = [{"agent_name": "fs", "upstream_url": "http://fs:8000"}]  # missing tenant_id
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps(entry))
        from yashigani.mcp.registry import build_registry_from_env
        with pytest.raises(RuntimeError, match="missing required fields"):
            build_registry_from_env(opa_url="http://policy:8181")

    def test_build_registry_one_server(self, monkeypatch):
        """One valid server entry → one broker registered."""
        entry = [{
            "agent_name": "filesystem-mcp",
            "upstream_url": "http://filesystem-mcp:8000",
            "tenant_id": "acme",
            "is_filesystem_agent": True,
        }]
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps(entry))
        from yashigani.mcp.registry import build_registry_from_env
        reg, store = build_registry_from_env(opa_url="http://policy:8181")
        assert len(reg) == 1
        assert store is not None
        result = reg.get("filesystem-mcp")
        assert result is not None
        _, server_cfg = result
        assert server_cfg.is_filesystem_agent is True
        assert server_cfg.tenant_id == "acme"


# ---------------------------------------------------------------------------
# JWKS Cache-Control fix (Nico)
# ---------------------------------------------------------------------------

class TestJwksCacheControl:
    """JWKS max-age must equal JWT TTL (60s) to close the rotation gap."""

    def test_cache_control_is_60s(self):
        from yashigani.mcp._jwks import JWKS_CACHE_CONTROL
        # Must be max-age=60 (== JWT TTL) — NOT max-age=300 which opens ~234s gap
        assert "max-age=60" in JWKS_CACHE_CONTROL, (
            f"Nico fix: JWKS_CACHE_CONTROL must contain 'max-age=60', got: {JWKS_CACHE_CONTROL!r}"
        )
        assert "must-revalidate" in JWKS_CACHE_CONTROL

    def test_router_uses_constant(self):
        """The router handler uses the constant — verify they match."""
        import inspect
        from yashigani.mcp import router as mcp_router_module
        from yashigani.mcp._jwks import JWKS_CACHE_CONTROL
        # The router sets Cache-Control from JWKS_CACHE_CONTROL — check the source
        source = inspect.getsource(mcp_router_module)
        assert "JWKS_CACHE_CONTROL" in source, (
            "router.py must reference JWKS_CACHE_CONTROL constant (not a hardcoded value)"
        )


# ---------------------------------------------------------------------------
# FIPS provider assertion (Nico)
# ---------------------------------------------------------------------------

class TestFipsProviderAssertion:
    """McpJwtIssuer must assert FIPS provider when FIPS_MODE=1."""

    def test_fips_mode_not_set_skips_assertion(self, monkeypatch):
        """When FIPS_MODE is unset, the assertion is a no-op."""
        monkeypatch.delenv("FIPS_MODE", raising=False)
        from yashigani.mcp._jwt import McpJwtIssuer
        # Should construct without raising
        issuer = McpJwtIssuer(tenant_id="test-tenant")
        assert issuer is not None

    def test_fips_mode_zero_skips_assertion(self, monkeypatch):
        """FIPS_MODE=0 is not FIPS mode — assertion is a no-op."""
        monkeypatch.setenv("FIPS_MODE", "0")
        from yashigani.mcp._jwt import McpJwtIssuer
        issuer = McpJwtIssuer(tenant_id="test-tenant")
        assert issuer is not None

    def test_fips_mode_one_fails_if_provider_absent(self, monkeypatch):
        """
        FIPS_MODE=1 with a subprocess returning no 'fips' in output → RuntimeError.
        """
        monkeypatch.setenv("FIPS_MODE", "1")
        from yashigani.mcp._jwt import McpJwtIssuer

        # Mock subprocess.run to simulate no FIPS provider
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Providers:\ndefault\nlegacy\n",
                stderr="",
            )
            with pytest.raises(RuntimeError, match="FIPS provider is NOT loaded"):
                McpJwtIssuer(tenant_id="test-tenant")

    def test_fips_mode_one_passes_if_provider_present(self, monkeypatch):
        """
        FIPS_MODE=1 with a subprocess returning 'fips' in output → no error.
        """
        monkeypatch.setenv("FIPS_MODE", "1")
        from yashigani.mcp._jwt import McpJwtIssuer

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Providers:\nfips\ndefault\n",
                stderr="",
            )
            # Should not raise
            issuer = McpJwtIssuer(tenant_id="test-tenant")
            assert issuer is not None

    def test_fips_mode_one_openssl_missing(self, monkeypatch):
        """FIPS_MODE=1 but openssl binary not found → RuntimeError."""
        monkeypatch.setenv("FIPS_MODE", "1")
        from yashigani.mcp._jwt import McpJwtIssuer

        with patch("subprocess.run", side_effect=FileNotFoundError("openssl not found")):
            with pytest.raises(RuntimeError, match="openssl.*binary not found"):
                McpJwtIssuer(tenant_id="test-tenant")


# ---------------------------------------------------------------------------
# mcp_router_runtime.py tests
# ---------------------------------------------------------------------------

def _make_mock_broker(allow: bool = True, deny_reason: str = "ok", issued_jwt: str = "test-jwt"):
    """Build a mock McpBroker with a configurable enforce() response."""
    from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

    broker = MagicMock()
    opa_dec = OpaDecision(
        allow=allow,
        deny_reason=deny_reason,
        redact_args=set(),
        audit_capture=False,
        rate_limit_key=None,
    )
    decision = BrokerDecision(
        call_id="test-call-id",
        allow=allow,
        deny_reason=deny_reason,
        opa_decision=opa_dec,
        issued_jwt=issued_jwt if allow else None,
    )
    broker.enforce = AsyncMock(return_value=decision)
    # G-ORCH-OPA-1: enforce_result must be an AsyncMock so the egress gate can
    # await it.  Default: allow (so existing tests that only check ingress pass).
    broker.enforce_result = AsyncMock(return_value=EgressDecision(
        allow=True,
        deny_reason="ok",
        policy_id="mcp.response_decision",
        code="MCP_RESULT_OK",
        user_message="Tool result approved for delivery.",
        elapsed_ms=1,
    ))
    broker._issuer = MagicMock()
    broker._issuer.issue = MagicMock(return_value="session-jwt-value")
    return broker


def _make_registry_with_server(
    agent_name: str = "filesystem-mcp",
    upstream_url: str = "http://fs-mcp:8000",
    is_filesystem_agent: bool = True,
    allow_tools_call: bool = True,
):
    from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

    reg = McpBrokerRegistry()
    broker = _make_mock_broker(allow=allow_tools_call)
    cfg = McpBrokerServerConfig(
        upstream_url=upstream_url,
        is_filesystem_agent=is_filesystem_agent,
        tenant_id="acme",
        agent_name=agent_name,
    )
    reg.register(agent_name, broker, cfg)
    return reg, broker


class TestMcpRuntimeRouter:
    """Tests for mcp_router_runtime.create_mcp_call_router."""

    def _build_app(self, registry):
        from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(create_mcp_call_router(registry))
        return app

    def test_unknown_agent_returns_404(self):
        """GET /mcp/{unknown} → 404."""
        reg, _ = _make_registry_with_server("known-agent")
        app = self._build_app(reg)
        client = TestClient(app)
        req = _make_jsonrpc_request("tools/call", req_id="1")
        resp = client.post("/mcp/unknown-agent", content=req)
        assert resp.status_code == 404
        assert resp.json()["error"] == "MCP_SERVER_NOT_FOUND"

    def test_tools_call_denied_returns_403(self):
        """broker.enforce() deny → 403 with deny_reason.  No transport call needed."""
        reg, _ = _make_registry_with_server(allow_tools_call=False)
        app = self._build_app(reg)

        # No patch needed: real posture derivation runs (McpHttpTransport.derive_posture
        # is a pure in-memory computation), and broker.enforce() is mocked to deny.
        client = TestClient(app)
        req = _make_jsonrpc_request(
            "tools/call", {"name": "read_file", "arguments": {"path": "/foo"}}, req_id="deny-1"
        )
        resp = client.post("/mcp/filesystem-mcp", content=req)

        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "MCP_TOOL_CALL_DENIED"

    def test_tools_call_allowed_forwards_upstream(self):
        """broker.enforce() allow → McpHttpTransport.forward() called."""
        reg, broker = _make_registry_with_server(allow_tools_call=True)
        app = self._build_app(reg)

        fake_upstream_response = json.dumps({
            "jsonrpc": "2.0", "id": "allow-1", "result": {"content": "file content"}
        })

        # The route code does:
        #   transport_descriptor = McpHttpTransport(...)         # for derive_posture()
        #   async with McpHttpTransport(...) as transport:       # for forward()
        #
        # We need the first call (derive_posture) to use the real class, and the
        # second call (the context-manager forward) to use a mock.
        # Simplest: let the real McpHttpTransport be used for derive_posture(),
        # and patch only the forward() method on the async-context instance.
        from yashigani.mcp._transport_http import McpHttpTransport as RealTransport

        original_aenter = RealTransport.__aenter__

        async def fake_aenter(self):
            self.forward = AsyncMock(return_value=fake_upstream_response)
            return self

        with patch.object(RealTransport, "__aenter__", fake_aenter):
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/foo"}}, req_id="allow-1"
            )
            resp = client.post("/mcp/filesystem-mcp", content=req)

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "allow-1"
        assert data["result"]["content"] == "file content"

        # Verify enforce() was called
        broker.enforce.assert_called_once()
        ctx = broker.enforce.call_args[0][0]
        assert ctx.tool_name == "read_file"
        assert ctx.agent_name == "filesystem-mcp"
        assert ctx.action == "mcp.tools.call"

    def test_initialize_passes_through_without_enforce(self):
        """'initialize' is a session message — broker.enforce() must NOT be called."""
        reg, broker = _make_registry_with_server()
        app = self._build_app(reg)

        fake_init_response = json.dumps({
            "jsonrpc": "2.0", "id": "init-1",
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}}
        })

        from yashigani.mcp._transport_http import McpHttpTransport as RealTransport

        async def fake_aenter(self):
            self.forward = AsyncMock(return_value=fake_init_response)
            return self

        with patch.object(RealTransport, "__aenter__", fake_aenter):
            client = TestClient(app)
            req = _make_jsonrpc_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            }, req_id="init-1")
            resp = client.post("/mcp/filesystem-mcp", content=req)

        assert resp.status_code == 200
        # enforce() must NOT have been called for session management messages
        broker.enforce.assert_not_called()

    def test_notification_returns_202(self):
        """Notification (no id) → 202, enforce() not called."""
        reg, broker = _make_registry_with_server()
        app = self._build_app(reg)

        from yashigani.mcp._transport_http import McpHttpTransport as RealTransport

        async def fake_aenter(self):
            self.forward = AsyncMock(return_value="{}")
            return self

        with patch.object(RealTransport, "__aenter__", fake_aenter):
            client = TestClient(app)
            notif = _make_jsonrpc_notification("notifications/initialized")
            resp = client.post("/mcp/filesystem-mcp", content=notif)

        assert resp.status_code == 202
        broker.enforce.assert_not_called()

    def test_xff_headers_stripped_posture_is_mcp_b(self):
        """
        X-Forwarded-For / X-Real-IP / X-Posture headers must be stripped.
        Posture must always be mcp-b for an HTTP channel (never mcp-a from headers).
        """
        reg, broker = _make_registry_with_server()
        app = self._build_app(reg)

        captured_ctx = {}

        async def capture_enforce(ctx):
            captured_ctx["ctx"] = ctx
            from yashigani.mcp._types import BrokerDecision, OpaDecision
            return BrokerDecision(
                call_id=ctx.call_id,
                allow=False,
                deny_reason="test_deny",
                opa_decision=OpaDecision(
                    allow=False, deny_reason="test_deny",
                    redact_args=set(), audit_capture=False, rate_limit_key=None,
                ),
            )

        broker.enforce = AsyncMock(side_effect=capture_enforce)

        client = TestClient(app)
        req = _make_jsonrpc_request("tools/call", {"name": "read_file"}, req_id="xff-1")
        client.post(
            "/mcp/filesystem-mcp",
            content=req,
            headers={
                "X-Forwarded-For": "10.0.0.1",
                "X-Real-IP": "10.0.0.1",
                "X-Posture": "mcp-a",  # attempt to inject mcp-a via header
            },
        )

        # Posture must be mcp-b (HTTP channel) regardless of injected headers
        assert "ctx" in captured_ctx
        from yashigani.mcp._types import McpPosture
        assert captured_ctx["ctx"].posture == McpPosture.MCP_B

    def test_invalid_json_body_returns_400(self):
        """Non-JSON body → 400."""
        reg, _ = _make_registry_with_server()
        app = self._build_app(reg)
        client = TestClient(app)
        resp = client.post("/mcp/filesystem-mcp", content=b"not-json{{{")
        assert resp.status_code == 400
        assert resp.json()["error"] == "INVALID_JSON"

    def test_upstream_error_returns_502(self):
        """McpHttpTransport.forward() raising HttpTransportError → 502."""
        from yashigani.mcp._transport_http import HttpTransportError, McpHttpTransport as RealTransport

        reg, _ = _make_registry_with_server(allow_tools_call=True)
        app = self._build_app(reg)

        async def fake_aenter_raise(self):
            self.forward = AsyncMock(side_effect=HttpTransportError("bridge down"))
            return self

        with patch.object(RealTransport, "__aenter__", fake_aenter_raise):
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file"}, req_id="upstream-err-1"
            )
            resp = client.post("/mcp/filesystem-mcp", content=req)

        assert resp.status_code == 502
        assert resp.json()["error"] == "UPSTREAM_UNREACHABLE"


# ---------------------------------------------------------------------------
# proxy.py — new params present in signature
# ---------------------------------------------------------------------------

class TestProxyNewParams:
    """create_gateway_app must accept mcp_broker_registry and mcp_jwks_store."""

    def test_new_params_accepted(self, monkeypatch):
        """
        create_gateway_app signature must include the two new optional params.
        Calling with explicit None values must not raise.
        """
        import inspect
        from yashigani.gateway.proxy import create_gateway_app

        sig = inspect.signature(create_gateway_app)
        assert "mcp_broker_registry" in sig.parameters, (
            "create_gateway_app must have mcp_broker_registry parameter"
        )
        assert "mcp_jwks_store" in sig.parameters, (
            "create_gateway_app must have mcp_jwks_store parameter"
        )
        # Both must be optional with default None
        assert sig.parameters["mcp_broker_registry"].default is None
        assert sig.parameters["mcp_jwks_store"].default is None

    def test_state_stores_mcp_objects(self, monkeypatch):
        """
        The _state dict inside create_gateway_app must include the two keys.
        We verify by inspecting the source for the key names.
        """
        import inspect
        from yashigani.gateway import proxy as proxy_module
        source = inspect.getsource(proxy_module.create_gateway_app)
        assert "mcp_broker_registry" in source
        assert "mcp_jwks_store" in source
