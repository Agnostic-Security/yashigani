"""
Regression tests — F-001: orchestrator brain call TLS verification.

What this tests:
  A. _call_orchestrator uses ollama_async_client (mesh-aware transport) instead
     of a bare httpx.AsyncClient.  Regression: bare client has no SSL context
     and raises CERTIFICATE_VERIFY_FAILED against https://caddy:11435/ollama
     (Mac Metal + any mTLS-Ollama deployment).

  B. _call_orchestrator passes the correct ollama_url and timeout to
     ollama_async_client so the https branch loads the internal PKI context.

  C. _call_orchestrator still works for plain http://ollama:11434 (Linux
     container path) — ollama_async_client falls through to a bare client
     for http URLs.

  D. _execute_mcp_tool (line ~549 audit site) uses internal_httpx_client for
     https:// upstream URLs — same gap patched in the same commit.

  E. _execute_mcp_tool uses plain httpx.AsyncClient for http:// upstream URLs
     (legacy / test path) — no regression on the non-mTLS path.

Last updated: 2026-07-12T00:00:00+00:00
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_ollama_response(content: str = "ok") -> MagicMock:
    """Build a mock httpx Response for Ollama /api/chat."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={
        "message": {"role": "assistant", "content": content, "tool_calls": None},
    })
    return resp


def _mock_async_client_cm(resp: MagicMock) -> MagicMock:
    """Build a mock async context manager that yields a mock httpx client."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=resp)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _mock_catalog(tools: list | None = None) -> MagicMock:
    cat = MagicMock()
    cat.tools = tools or []
    return cat


# ---------------------------------------------------------------------------
# A + B. _call_orchestrator uses ollama_async_client (F-001 primary fix)
# ---------------------------------------------------------------------------

class TestCallOrchestratorSslContext:
    """_call_orchestrator must use ollama_async_client, not bare httpx.AsyncClient."""

    async def test_https_ollama_url_routes_through_ollama_async_client(self):
        """
        When ollama_url is https://caddy:11435/ollama, _call_orchestrator MUST
        call ollama_async_client (not httpx.AsyncClient directly).

        Regression: the old code did
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(url, ...)
        which has no SSL context and fails CERTIFICATE_VERIFY_FAILED on the
        Mac Metal mTLS front.

        The fix imports ollama_async_client from _ollama_transport; that helper
        returns internal_httpx_client() for https:// URLs (PKI-verified, TLS 1.3,
        client cert presented) and a plain client for http:// URLs.
        """
        https_url = "https://caddy:11435/ollama"
        mock_resp = _mock_ollama_response("test response")
        mock_cm = _mock_async_client_cm(mock_resp)

        mock_ollama_async_client = MagicMock(return_value=mock_cm)

        mock_state = MagicMock()
        mock_state.ollama_url = https_url

        with patch("yashigani.inspection._ollama_transport.ollama_async_client",
                   mock_ollama_async_client), \
             patch("yashigani.gateway.openai_router._state", mock_state):
            from yashigani.gateway.orchestrator import _call_orchestrator
            result = await _call_orchestrator(
                messages=[{"role": "user", "content": "hi"}],
                catalog=_mock_catalog(),
                model="llama3.2:3b",
            )

        # ollama_async_client MUST have been called.
        mock_ollama_async_client.assert_called_once()
        call_args = mock_ollama_async_client.call_args

        # First positional argument is the ollama_url.
        assert call_args[0][0] == https_url, (
            f"ollama_async_client must receive the ollama_url ({https_url!r}) "
            f"so it can select the PKI-verified client for https; "
            f"got {call_args[0][0]!r}"
        )

        # timeout must be 120.0.
        timeout_kwarg = call_args[1].get("timeout")
        timeout_pos = call_args[0][1] if len(call_args[0]) > 1 else None
        assert (timeout_kwarg == 120.0 or timeout_pos == 120.0), (
            "ollama_async_client must be called with timeout=120.0"
        )

        # Result structure is correct.
        assert result["role"] == "assistant"
        assert "tool_calls" in result

    async def test_call_orchestrator_result_shape(self):
        """_call_orchestrator returns the expected dict keys after the fix."""
        mock_resp = _mock_ollama_response("hello")
        mock_cm = _mock_async_client_cm(mock_resp)

        with patch("yashigani.inspection._ollama_transport.ollama_async_client",
                   MagicMock(return_value=mock_cm)), \
             patch("yashigani.gateway.openai_router._state",
                   MagicMock(ollama_url="https://caddy:11435/ollama")):
            from yashigani.gateway.orchestrator import _call_orchestrator
            result = await _call_orchestrator(
                messages=[{"role": "user", "content": "ping"}],
                catalog=_mock_catalog(),
                model="llama3.2:3b",
            )

        assert set(result.keys()) >= {"role", "content", "tool_calls"}, (
            f"result must have role/content/tool_calls; got {set(result.keys())}"
        )
        assert result["role"] == "assistant"
        assert result["content"] == "hello"
        assert result["tool_calls"] == []


# ---------------------------------------------------------------------------
# C. http URL — no SSL context overhead, plain client still works
# ---------------------------------------------------------------------------

class TestCallOrchestratorHttpPath:
    """Plain http://ollama:11434 must still work after the fix."""

    async def test_http_ollama_url_routes_through_ollama_async_client(self):
        """
        ollama_async_client returns a plain httpx.AsyncClient for http:// URLs;
        _call_orchestrator must still call ollama_async_client (not a bare client)
        and the http path must work correctly.
        """
        http_url = "http://ollama:11434"
        mock_resp = _mock_ollama_response("pong")
        mock_cm = _mock_async_client_cm(mock_resp)
        mock_ollama_async_client = MagicMock(return_value=mock_cm)

        with patch("yashigani.inspection._ollama_transport.ollama_async_client",
                   mock_ollama_async_client), \
             patch("yashigani.gateway.openai_router._state",
                   MagicMock(ollama_url=http_url)):
            from yashigani.gateway.orchestrator import _call_orchestrator
            result = await _call_orchestrator(
                messages=[{"role": "user", "content": "ping"}],
                catalog=_mock_catalog(),
                model="llama3.2:3b",
            )

        # ollama_async_client must still be called — not a bare client.
        mock_ollama_async_client.assert_called_once()
        assert mock_ollama_async_client.call_args[0][0] == http_url

        assert result["role"] == "assistant"
        assert result["content"] == "pong"


# ---------------------------------------------------------------------------
# D. _execute_mcp_tool: https upstream → internal_httpx_client (audit fix)
# ---------------------------------------------------------------------------

class TestExecuteMcpToolSslContext:
    """
    _execute_mcp_tool must use internal_httpx_client for https:// upstream URLs.

    The MCP upstream URL in production is https://caddy:<port>/mcp/<tenant>/<server>
    (see manifest/codegen.py lines ~3592).  The old bare httpx.AsyncClient would
    fail CERTIFICATE_VERIFY_FAILED against this mTLS front exactly like F-001.
    """

    def _make_opa_allow(self) -> dict:
        return {"allow": True, "reason": "ok"}

    def _make_mock_mcp_resp(self, content: str = "tool result") -> MagicMock:
        resp = MagicMock()
        resp.json = MagicMock(return_value={
            "jsonrpc": "2.0", "id": "req-1",
            "result": {"content": [{"type": "text", "text": content}]},
        })
        return resp

    async def test_https_mcp_upstream_uses_internal_httpx_client(self):
        """
        When upstream_url starts with https://, _execute_mcp_tool must use
        internal_httpx_client (PKI-verified client), not bare httpx.AsyncClient.
        """
        upstream_url = "https://caddy:11435/mcp/tenant1/filesystem"
        mock_resp = self._make_mock_mcp_resp("file contents")
        mock_cm = _mock_async_client_cm(mock_resp)
        mock_internal = MagicMock(return_value=mock_cm)

        # Wire all the complex gateway dependencies to no-ops / allows.
        with patch("yashigani.gateway.orchestrator._opa_ingress_for_mcp",
                   AsyncMock(return_value=self._make_opa_allow())), \
             patch("yashigani.gateway.orchestrator._inspect_result",
                   MagicMock(return_value=("PASS", 0.99, {}))), \
             patch("yashigani.gateway.orchestrator._classify_sensitivity",
                   MagicMock(return_value="PUBLIC")), \
             patch("yashigani.gateway.orchestrator._opa_egress_for_mcp_result",
                   AsyncMock(return_value={"allow": True, "reason": "ok"})), \
             patch("yashigani.gateway.orchestrator._audit", MagicMock()), \
             patch("yashigani.pki.client.internal_httpx_client", mock_internal):
            from yashigani.gateway.orchestrator import _execute_mcp_tool
            result = await _execute_mcp_tool(
                server="filesystem",
                upstream_url=upstream_url,
                tool="read_file",
                args={"path": "/tmp/test.txt"},
                identity={"identity_id": "idnt_test", "groups": []},
                depth=1,
                root_rid="root-123",
                request_id="req-1",
            )

        # internal_httpx_client must have been called (PKI-verified path).
        mock_internal.assert_called_once_with(timeout=120.0), (
            f"https MCP upstream must call internal_httpx_client(timeout=120.0); "
            f"got calls: {mock_internal.call_args_list}"
        )

        # Result must not be a blocked/error state.
        assert not result.blocked, (
            f"MCP call must succeed on mocked allow; got blocked=True: {result.text!r}"
        )

    async def test_http_mcp_upstream_uses_plain_httpx_async_client(self):
        """
        When upstream_url starts with http://, _execute_mcp_tool must use a
        plain httpx.AsyncClient — NOT internal_httpx_client.  This preserves
        backwards-compatibility with non-mTLS MCP servers (dev/test).
        """
        upstream_url = "http://localhost:3001/mcp"
        mock_resp = self._make_mock_mcp_resp("dev tool result")
        mock_cm = _mock_async_client_cm(mock_resp)

        mock_internal = MagicMock(return_value=mock_cm)
        mock_plain = MagicMock(return_value=mock_cm)

        with patch("yashigani.gateway.orchestrator._opa_ingress_for_mcp",
                   AsyncMock(return_value=self._make_opa_allow())), \
             patch("yashigani.gateway.orchestrator._inspect_result",
                   MagicMock(return_value=("PASS", 0.99, {}))), \
             patch("yashigani.gateway.orchestrator._classify_sensitivity",
                   MagicMock(return_value="PUBLIC")), \
             patch("yashigani.gateway.orchestrator._opa_egress_for_mcp_result",
                   AsyncMock(return_value={"allow": True, "reason": "ok"})), \
             patch("yashigani.gateway.orchestrator._audit", MagicMock()), \
             patch("yashigani.pki.client.internal_httpx_client", mock_internal), \
             patch("httpx.AsyncClient", mock_plain):
            from yashigani.gateway.orchestrator import _execute_mcp_tool
            result = await _execute_mcp_tool(
                server="dev-server",
                upstream_url=upstream_url,
                tool="list",
                args={},
                identity={"identity_id": "idnt_test", "groups": []},
                depth=1,
                root_rid="root-456",
                request_id="req-2",
            )

        # internal_httpx_client must NOT be called for http:// URLs.
        mock_internal.assert_not_called(), (
            "http:// MCP upstream must NOT call internal_httpx_client — "
            "that would require PKI certs in dev/test environments"
        )

        # The plain client must be used.
        mock_plain.assert_called_once_with(timeout=120.0)

        assert not result.blocked


# ---------------------------------------------------------------------------
# E. ollama_async_client scheme-selection unit check (belt-and-suspenders)
# ---------------------------------------------------------------------------

class TestOllamaAsyncClientSchemeSelection:
    """
    Direct unit test of ollama_async_client so a refactor of _ollama_transport
    that breaks the https branch is caught before it reaches _call_orchestrator.
    """

    def test_https_scheme_returns_internal_client(self):
        """ollama_async_client("https://...") must call internal_httpx_client."""
        mock_internal_client = MagicMock(spec=["timeout"])
        mock_internal_client.timeout = 30.0

        with patch("yashigani.pki.client.internal_httpx_client",
                   MagicMock(return_value=mock_internal_client)) as mock_factory:
            from yashigani.inspection._ollama_transport import ollama_async_client
            client = ollama_async_client("https://caddy:11435/ollama", timeout=120.0)

        mock_factory.assert_called_once(), (
            "ollama_async_client for https:// must call internal_httpx_client"
        )
        # Timeout must be applied.
        assert mock_internal_client.timeout == 120.0

    def test_http_scheme_returns_plain_httpx(self):
        """ollama_async_client("http://...") must NOT call internal_httpx_client."""
        with patch("yashigani.pki.client.internal_httpx_client") as mock_factory:
            import httpx
            from yashigani.inspection._ollama_transport import ollama_async_client
            client = ollama_async_client("http://ollama:11434", timeout=30.0)

        mock_factory.assert_not_called(), (
            "ollama_async_client for http:// must NOT call internal_httpx_client"
        )
        assert isinstance(client, httpx.AsyncClient), (
            "http:// path must return a plain httpx.AsyncClient"
        )
