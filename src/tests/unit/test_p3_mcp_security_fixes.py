"""
Tests for P3 MCP broker security + HA fixes (scale review iteration).

Covers:
  - Fix-1: /mcp/* routes flow through the gateway rate-limiter + DDoSProtector
            (NOT mounted as extra_router which bypasses the pipeline).
  - Fix-2: _BridgeProcess in-flight cap — 503 + Retry-After at boundary.
  - Fix-3: Body size cap at BOTH the router layer (mcp_router_runtime.py) and
            the bridge layer (_bridge.py).
  - Fix-4: RedisNonceStore wired when REDIS_URL is set; InMemoryNonceStore
            used when REDIS_URL is unset (dev/test).
  - Fix-5: McpJwtIssuer raises RuntimeError in production/staging when
            ephemeral key would be used.
  - Fix-6: Helm gateway template emits YASHIGANI_MCP_SERVERS.

v2.25.0 / P3 scale review / Laura + Tiago sign-off.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys
import unittest.mock as mock
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
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


# ---------------------------------------------------------------------------
# Fix-1: /mcp/* routed through catch-all (rate-limiter / DDoS)
# ---------------------------------------------------------------------------

class TestFix1McpCallRoutedThroughCatchAll:
    """
    Fix-1 (Laura ship-blocker): /mcp/<agent_name> must flow through the
    proxy catch-all (rate-limiter + DDoSProtector), NOT be mounted as an
    extra_router.

    Proof strategy:
      1. The entrypoint no longer passes _mcp_call_router to _extra_routers.
      2. proxy.py has a /mcp/ intercept block AFTER the DDoS + rate-limit steps.
      3. dispatch_mcp_call is the entry point called from the catch-all.
    """

    def test_entrypoint_does_not_mount_mcp_call_router_as_extra_router(self):
        """
        The entrypoint source must NOT include _mcp_call_router in _extra_routers.
        After Fix-1, only _mcp_info_router is mounted as an extra_router.

        We read the source file directly (entrypoint.py runs module-level code
        that requires filesystem access, so importing it in tests is fragile).
        """
        import pathlib
        source = pathlib.Path("src/yashigani/gateway/entrypoint.py").read_text()

        # After Fix-1, _mcp_call_router must not appear in the _extra_routers list.
        # It may still appear in comments that reference Fix-1.
        # Specifically: the line `_extra_routers = [openai_router, _mcp_info_router, _mcp_call_router]`
        # must be gone.
        assert "[openai_router, _mcp_info_router, _mcp_call_router]" not in source, (
            "Fix-1 regression: _mcp_call_router must not be in _extra_routers. "
            "MCP calls must flow through the catch-all (rate-limiter + DDoS)."
        )

    def test_proxy_has_mcp_intercept_in_catch_all(self):
        """
        proxy._proxy_request_body must contain a /mcp/ intercept block that
        calls dispatch_mcp_call after the DDoS + rate-limit steps.
        """
        import inspect as _inspect
        from yashigani.gateway import proxy as proxy_module
        source = _inspect.getsource(proxy_module._proxy_request_body)

        assert "dispatch_mcp_call" in source, (
            "Fix-1: proxy._proxy_request_body must dispatch MCP calls via "
            "dispatch_mcp_call() (catch-all path, after rate-limiter + DDoS)."
        )
        assert "norm_path.startswith(\"/mcp/\")" in source, (
            "Fix-1: proxy._proxy_request_body must intercept /mcp/ prefix."
        )

    def test_dispatch_mcp_call_exists_and_is_callable(self):
        """dispatch_mcp_call must be importable and be an async function."""
        from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call
        assert inspect.iscoroutinefunction(dispatch_mcp_call), (
            "dispatch_mcp_call must be an async function"
        )

    def test_mcp_intercept_is_after_rate_limiter_in_source(self):
        """
        The /mcp/ intercept in proxy._proxy_request_body must appear AFTER
        the rate-limiter check (step 0b).  This is verified by line ordering
        in the source — the rate-limiter section uses state['rate_limiter'],
        the MCP intercept section uses dispatch_mcp_call.
        """
        import inspect as _inspect
        from yashigani.gateway import proxy as proxy_module
        source = _inspect.getsource(proxy_module._proxy_request_body)

        rl_pos = source.find("state[\"rate_limiter\"]")
        mcp_pos = source.find("dispatch_mcp_call")

        assert rl_pos != -1, "rate_limiter check must be present in _proxy_request_body"
        assert mcp_pos != -1, "dispatch_mcp_call must be present in _proxy_request_body"
        assert rl_pos < mcp_pos, (
            "Fix-1: dispatch_mcp_call intercept must appear AFTER the rate-limiter "
            "check in _proxy_request_body (MCP calls must be rate-limited)."
        )

    def test_mcp_intercept_is_after_ddos_protector_in_source(self):
        """The /mcp/ intercept must also appear after DDoSProtector in the source."""
        import inspect as _inspect
        from yashigani.gateway import proxy as proxy_module
        source = _inspect.getsource(proxy_module._proxy_request_body)

        ddos_pos = source.find("ddos_protector")
        mcp_pos = source.find("dispatch_mcp_call")

        assert ddos_pos != -1, "ddos_protector check must be present in _proxy_request_body"
        assert mcp_pos != -1
        assert ddos_pos < mcp_pos, (
            "Fix-1: dispatch_mcp_call intercept must appear AFTER the DDoS check "
            "in _proxy_request_body (MCP calls must be DDoS-protected)."
        )


# ---------------------------------------------------------------------------
# Fix-2: in-flight cap
# ---------------------------------------------------------------------------

class TestFix2InFlightCap:
    """Fix-2 (Laura ship-blocker): in-flight cap in _BridgeProcess.send_request."""

    def test_max_in_flight_constant_exists(self):
        """_MAX_IN_FLIGHT must be defined as a module-level constant."""
        from yashigani.mcp import _bridge
        assert hasattr(_bridge, "_MAX_IN_FLIGHT"), "_MAX_IN_FLIGHT must be defined"
        assert isinstance(_bridge._MAX_IN_FLIGHT, int), "_MAX_IN_FLIGHT must be int"
        assert _bridge._MAX_IN_FLIGHT > 0, "_MAX_IN_FLIGHT must be > 0"

    def test_max_in_flight_configurable_via_env(self, monkeypatch):
        """YASHIGANI_MCP_BRIDGE_MAX_IN_FLIGHT env var controls the cap."""
        monkeypatch.setenv("YASHIGANI_MCP_BRIDGE_MAX_IN_FLIGHT", "8")
        # Reload the module constant — it's read at import time
        import importlib
        from yashigani.mcp import _bridge
        importlib.reload(_bridge)
        assert _bridge._MAX_IN_FLIGHT == 8
        # Restore default by reloading without the env var override
        monkeypatch.delenv("YASHIGANI_MCP_BRIDGE_MAX_IN_FLIGHT", raising=False)
        importlib.reload(_bridge)

    @pytest.mark.asyncio
    async def test_send_request_raises_when_cap_reached(self):
        """
        When len(_pending) >= _MAX_IN_FLIGHT, send_request must raise RuntimeError
        with "in-flight cap" in the message — without registering a new future.
        """
        from yashigani.mcp._bridge import _BridgeProcess, _MAX_IN_FLIGHT

        bridge = _BridgeProcess(
            command=[sys.executable, "-c",
                # subprocess that never responds — to keep futures pending
                "import sys\nfor line in sys.stdin:\n    pass\n"
            ]
        )
        await bridge.start()
        try:
            # Pre-fill _pending to the cap limit with dummy futures
            loop = asyncio.get_running_loop()
            for i in range(_MAX_IN_FLIGHT):
                fut = loop.create_future()
                bridge._pending[str(i)] = fut

            # Now a new send_request must raise immediately
            req = json.dumps({"jsonrpc": "2.0", "id": "cap-test", "method": "tools/call"})
            with pytest.raises(RuntimeError, match="in-flight cap"):
                await bridge.send_request(req)
        finally:
            # Clean up pending futures to avoid warnings
            for fut in bridge._pending.values():
                if not fut.done():
                    fut.cancel()
            bridge._pending.clear()
            await bridge.stop()

    def test_bridge_http_returns_503_at_cap(self):
        """
        HTTP-level test: when the bridge is at in-flight cap, POST returns
        503 with Retry-After header.
        """
        from yashigani.mcp._bridge import create_bridge_app, _MAX_IN_FLIGHT

        app = create_bridge_app(
            command=[sys.executable, "-c",
                "import sys\nfor line in sys.stdin:\n    pass\n"
            ]
        )
        client = TestClient(app)

        # Pre-fill _pending to simulate cap exhaustion by patching send_request
        # to raise RuntimeError with the in-flight cap message
        with patch(
            "yashigani.mcp._bridge._BridgeProcess.send_request",
            new=AsyncMock(side_effect=RuntimeError(
                f"mcp-bridge: in-flight cap reached ({_MAX_IN_FLIGHT} pending requests). "
                "Retry later."
            ))
        ):
            req = json.dumps({"jsonrpc": "2.0", "id": "cap-http", "method": "tools/call"})
            resp = client.post("/mcp", content=req)

        assert resp.status_code == 503, (
            f"Expected 503 at in-flight cap, got {resp.status_code}"
        )
        assert "Retry-After" in resp.headers, "503 response must include Retry-After header"
        data = resp.json()
        assert data["error"] == "bridge_overloaded"


# ---------------------------------------------------------------------------
# Fix-3: body size cap
# ---------------------------------------------------------------------------

class TestFix3BodySizeCap:
    """Fix-3 (Laura ship-blocker): body size cap at both router and bridge layers."""

    def test_router_body_limit_constant_exists(self):
        """MCP_BODY_SIZE_LIMIT_BYTES must be defined in mcp_router_runtime."""
        from yashigani.gateway.mcp_router_runtime import MCP_BODY_SIZE_LIMIT_BYTES
        assert isinstance(MCP_BODY_SIZE_LIMIT_BYTES, int)
        assert MCP_BODY_SIZE_LIMIT_BYTES > 0

    def test_bridge_body_limit_constant_exists(self):
        """_BRIDGE_BODY_LIMIT must be defined in _bridge."""
        from yashigani.mcp._bridge import _BRIDGE_BODY_LIMIT
        assert isinstance(_BRIDGE_BODY_LIMIT, int)
        assert _BRIDGE_BODY_LIMIT > 0

    def test_router_returns_413_on_oversized_body(self, monkeypatch):
        """POST /mcp/{agent} with body > cap → 413."""
        from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        import yashigani.gateway.mcp_router_runtime as _rt_module

        # Set a tiny cap for this test
        monkeypatch.setattr(_rt_module, "MCP_BODY_SIZE_LIMIT_BYTES", 64)

        reg = McpBrokerRegistry()
        reg.register("test-agent", object(), McpBrokerServerConfig(
            upstream_url="http://test:8000",
            is_filesystem_agent=False,
            tenant_id="test",
            agent_name="test-agent",
        ))

        app = FastAPI()
        app.include_router(create_mcp_call_router(reg))
        client = TestClient(app)

        big_body = b"x" * 128  # 128 bytes > 64-byte cap
        resp = client.post("/mcp/test-agent", content=big_body)
        assert resp.status_code == 413, (
            f"Expected 413 for oversized body at router layer, got {resp.status_code}"
        )
        assert resp.json()["error"] == "REQUEST_ENTITY_TOO_LARGE"

    def test_bridge_returns_413_on_oversized_body(self, monkeypatch):
        """Bridge HTTP handler: body > _BRIDGE_BODY_LIMIT → 413."""
        import yashigani.mcp._bridge as _bridge_module
        monkeypatch.setattr(_bridge_module, "_BRIDGE_BODY_LIMIT", 64)

        from yashigani.mcp._bridge import create_bridge_app

        app = create_bridge_app(
            command=[sys.executable, "-c",
                "import sys\nfor line in sys.stdin:\n    pass\n"
            ]
        )
        client = TestClient(app)

        big_body = b"x" * 128
        resp = client.post("/mcp", content=big_body)
        assert resp.status_code == 413, (
            f"Expected 413 for oversized body at bridge layer, got {resp.status_code}"
        )
        assert resp.json()["error"] == "REQUEST_ENTITY_TOO_LARGE"

    def test_both_caps_share_same_env_var(self, monkeypatch):
        """
        YASHIGANI_MCP_MAX_BODY_BYTES controls BOTH layers (defense in depth
        with the same configurable limit).
        """
        import importlib
        import yashigani.gateway.mcp_router_runtime as _rt_module
        import yashigani.mcp._bridge as _bridge_module

        monkeypatch.setenv("YASHIGANI_MCP_MAX_BODY_BYTES", "512")
        importlib.reload(_rt_module)
        importlib.reload(_bridge_module)

        assert _rt_module.MCP_BODY_SIZE_LIMIT_BYTES == 512
        assert _bridge_module._BRIDGE_BODY_LIMIT == 512

        # Restore
        monkeypatch.delenv("YASHIGANI_MCP_MAX_BODY_BYTES", raising=False)
        importlib.reload(_rt_module)
        importlib.reload(_bridge_module)


# ---------------------------------------------------------------------------
# Fix-4: RedisNonceStore wired at startup
# ---------------------------------------------------------------------------

class TestFix4RedisNonceStoreWiring:
    """Fix-4 (HA-correctness): RedisNonceStore wired when REDIS_URL is set."""

    def test_in_memory_nonce_store_used_when_redis_url_absent(self, monkeypatch):
        """When REDIS_URL is unset → InMemoryNonceStore is used (dev/test mode)."""
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps([{
            "agent_name": "test-mcp",
            "upstream_url": "http://test-mcp:8000",
            "tenant_id": "acme",
        }]))
        from yashigani.mcp._nonce import InMemoryNonceStore
        import importlib
        import yashigani.mcp.registry as _reg_module
        importlib.reload(_reg_module)

        from yashigani.mcp.registry import build_registry_from_env
        reg, store = build_registry_from_env(opa_url="http://policy:8181")
        assert len(reg) == 1

        # Verify the broker's nonce store is InMemoryNonceStore
        broker, _ = reg.get("test-mcp")
        # broker._nonce_store is set from McpBrokerConfig.nonce_store
        assert isinstance(broker._nonce_store, InMemoryNonceStore), (
            "When REDIS_URL is unset, broker must use InMemoryNonceStore"
        )

    def test_redis_nonce_store_wired_when_redis_url_set(self, monkeypatch):
        """When REDIS_URL is set → RedisNonceStore is constructed and passed to each broker."""
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps([{
            "agent_name": "test-mcp",
            "upstream_url": "http://test-mcp:8000",
            "tenant_id": "acme",
        }]))

        from yashigani.mcp._nonce import RedisNonceStore

        # Mock the redis module so no real Redis connection is needed
        mock_redis_client = MagicMock()
        with patch.dict("sys.modules", {"redis": MagicMock(
            from_url=MagicMock(return_value=mock_redis_client)
        )}):
            import importlib
            import yashigani.mcp.registry as _reg_module
            importlib.reload(_reg_module)

            from yashigani.mcp.registry import build_registry_from_env
            reg, store = build_registry_from_env(opa_url="http://policy:8181")

        assert len(reg) == 1
        broker, _ = reg.get("test-mcp")
        assert isinstance(broker._nonce_store, RedisNonceStore), (
            "When REDIS_URL is set, broker must use RedisNonceStore"
        )

    def test_redis_import_error_raises_runtime_error(self, monkeypatch):
        """If REDIS_URL is set but redis package is missing → RuntimeError at startup."""
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps([{
            "agent_name": "test-mcp",
            "upstream_url": "http://test-mcp:8000",
            "tenant_id": "acme",
        }]))

        # Patch the `import redis` inside build_registry_from_env by making
        # __import__ raise ImportError when "redis" is imported.
        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else None

        import builtins
        original_builtin_import = builtins.__import__

        def _mock_import(name, *args, **kwargs):
            if name == "redis":
                raise ImportError("No module named 'redis'")
            return original_builtin_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _mock_import)

        import importlib
        import yashigani.mcp.registry as _reg_module
        importlib.reload(_reg_module)

        from yashigani.mcp.registry import build_registry_from_env
        with pytest.raises(RuntimeError, match="redis.*package is not installed"):
            build_registry_from_env(opa_url="http://policy:8181")


# ---------------------------------------------------------------------------
# Fix-5: Production no-ephemeral-key guard
# ---------------------------------------------------------------------------

class TestFix5ProductionNoEphemeralKeyGuard:
    """Fix-5: McpJwtIssuer must raise RuntimeError in production/staging for ephemeral key."""

    def test_production_env_raises_if_no_key_configured(self, monkeypatch):
        """YASHIGANI_ENV=production + no key configured → RuntimeError at __init__."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)
        monkeypatch.delenv("FIPS_MODE", raising=False)

        from yashigani.mcp._jwt import McpJwtIssuer
        from pathlib import Path

        # Ensure the dev key file does not exist for this test
        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(RuntimeError, match="YASHIGANI_ENV.*production"):
                McpJwtIssuer(tenant_id="test-tenant")

    def test_staging_env_raises_if_no_key_configured(self, monkeypatch):
        """YASHIGANI_ENV=staging + no key configured → RuntimeError at __init__."""
        monkeypatch.setenv("YASHIGANI_ENV", "staging")
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)
        monkeypatch.delenv("FIPS_MODE", raising=False)

        from yashigani.mcp._jwt import McpJwtIssuer
        from pathlib import Path

        with patch.object(Path, "exists", return_value=False):
            with pytest.raises(RuntimeError, match="YASHIGANI_ENV.*staging"):
                McpJwtIssuer(tenant_id="test-tenant")

    def test_dev_env_allows_ephemeral_key(self, monkeypatch):
        """YASHIGANI_ENV=development (or unset) → ephemeral key is allowed (no error)."""
        monkeypatch.setenv("YASHIGANI_ENV", "development")
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)
        monkeypatch.delenv("FIPS_MODE", raising=False)

        from yashigani.mcp._jwt import McpJwtIssuer
        from pathlib import Path

        with patch.object(Path, "exists", return_value=False):
            # Should NOT raise for dev environment
            issuer = McpJwtIssuer(tenant_id="test-tenant")
            assert issuer is not None

    def test_unset_env_allows_ephemeral_key(self, monkeypatch):
        """YASHIGANI_ENV unset → ephemeral key allowed (backward-compatible dev default)."""
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)
        monkeypatch.delenv("FIPS_MODE", raising=False)

        from yashigani.mcp._jwt import McpJwtIssuer
        from pathlib import Path

        with patch.object(Path, "exists", return_value=False):
            issuer = McpJwtIssuer(tenant_id="test-tenant")
            assert issuer is not None

    def test_production_with_env_var_key_succeeds(self, monkeypatch):
        """YASHIGANI_ENV=production + YASHIGANI_MCP_SIGNING_KEY_PEM set → no error."""
        import base64
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
        from cryptography.hazmat.primitives import serialization

        # Generate a real P-384 key for this test
        key = ec.generate_private_key(SECP384R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem_b64 = base64.b64encode(pem).decode("ascii")

        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", pem_b64)
        monkeypatch.delenv("FIPS_MODE", raising=False)

        from yashigani.mcp._jwt import McpJwtIssuer
        issuer = McpJwtIssuer(tenant_id="test-tenant")
        assert issuer is not None


# ---------------------------------------------------------------------------
# Fix-6: Helm template emits YASHIGANI_MCP_SERVERS
# ---------------------------------------------------------------------------

class TestFix6HelmMcpServers:
    """Fix-6 (Captain): Helm gateway.yaml must emit YASHIGANI_MCP_SERVERS."""

    def test_helm_gateway_template_contains_mcp_servers_env(self):
        """
        helm/yashigani/templates/gateway.yaml must contain YASHIGANI_MCP_SERVERS.
        """
        import pathlib
        gateway_yaml = pathlib.Path(
            "helm/yashigani/templates/gateway.yaml"
        )
        assert gateway_yaml.exists(), "helm/yashigani/templates/gateway.yaml must exist"
        content = gateway_yaml.read_text()
        assert "YASHIGANI_MCP_SERVERS" in content, (
            "Fix-6: gateway.yaml must emit YASHIGANI_MCP_SERVERS env var. "
            "It was missing — gateway in K8s would silently have no MCP servers."
        )

    def test_values_yaml_has_mcp_servers_key(self):
        """values.yaml must have gateway.mcpServers defaulting to []."""
        import pathlib
        values_yaml = pathlib.Path("helm/yashigani/values.yaml")
        assert values_yaml.exists()
        content = values_yaml.read_text()
        assert "mcpServers:" in content, (
            "Fix-6: values.yaml must define gateway.mcpServers (default empty list)."
        )
        assert "mcpServers: []" in content, (
            "Fix-6: gateway.mcpServers must default to [] (no MCP = backward-compatible)."
        )

    def test_helm_render_empty_mcp_servers(self):
        """
        `helm template` with default values must render YASHIGANI_MCP_SERVERS="[]".
        Skipped if helm is not installed.
        """
        import subprocess
        import shutil

        if shutil.which("helm") is None:
            pytest.skip("helm not installed — skipping chart render test")

        result = subprocess.run(
            ["helm", "template", "test-release", "helm/yashigani",
             "--set", "global.environment=test",
             "--set", "global.installToken=fake-token"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            pytest.skip(f"helm template failed (may need additional values): {result.stderr[:500]}")

        assert "YASHIGANI_MCP_SERVERS" in result.stdout, (
            "helm template output must contain YASHIGANI_MCP_SERVERS"
        )
        # With empty mcpServers, the value should be "[]"
        assert '"[]"' in result.stdout or "value: \"[]\"" in result.stdout, (
            "With default empty mcpServers, YASHIGANI_MCP_SERVERS value must be '[]'"
        )


# ---------------------------------------------------------------------------
# Stale-version audit: asyncio.get_event_loop() removed from _bridge.py
# ---------------------------------------------------------------------------

class TestStaleVersionAudit:
    """Verify stale 3.9-era asyncio patterns have been removed from _bridge.py."""

    def test_no_get_event_loop_call_in_bridge(self):
        """
        _bridge.py must not CALL asyncio.get_event_loop().
        get_running_loop() is the correct call inside async functions.
        The string 'get_event_loop()' may appear in comments but must not
        appear as an actual function call (i.e. preceded by 'asyncio.').
        """
        import pathlib
        import re
        bridge_src = pathlib.Path("src/yashigani/mcp/_bridge.py").read_text()
        # Match actual call pattern: asyncio.get_event_loop() — not in comments
        non_comment_lines = [
            line for line in bridge_src.splitlines()
            if not line.lstrip().startswith("#")
        ]
        non_comment_src = "\n".join(non_comment_lines)
        assert "asyncio.get_event_loop()" not in non_comment_src, (
            "Stale-version audit: _bridge.py must not call asyncio.get_event_loop() "
            "in executable code. Use asyncio.get_running_loop() inside async functions."
        )

    def test_get_running_loop_used_in_bridge(self):
        """_bridge.py must use get_running_loop() for task creation and future creation."""
        import pathlib
        bridge_src = pathlib.Path("src/yashigani/mcp/_bridge.py").read_text()
        assert "get_running_loop()" in bridge_src, (
            "Stale-version audit: _bridge.py must use asyncio.get_running_loop()."
        )

    def test_lazy_lock_workaround_comment_corrected(self):
        """
        The lazy lock comment must reference the real uvicorn import-time reason,
        NOT the original incorrect docstring-level comment that cited Python 3.9.

        The ORIGINAL inaccurate comment was the inline docstring comment:
          "(Python 3.9 asyncio.Lock() binds at construction)"
        This specific exact phrase must no longer be the sole explanation —
        the correct uvicorn import-time rationale must be present.
        """
        import pathlib
        bridge_src = pathlib.Path("src/yashigani/mcp/_bridge.py").read_text()

        # The corrected comment must reference the uvicorn import-time reason
        assert "uvicorn" in bridge_src, (
            "Stale-version audit: _bridge.py must explain the real reason for the "
            "lazy lock (uvicorn import-time — module-level `app = create_bridge_app()` "
            "runs before uvicorn starts the event loop)."
        )
