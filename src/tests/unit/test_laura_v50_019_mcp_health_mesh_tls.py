"""
LAURA-V50-019 (Med) — ``mcp/router.py::_opa_health_check`` used a bare
``httpx.AsyncClient(timeout=2.0)`` with no mesh CA/mTLS trust.  Against a
mesh-mTLS OPA (require_and_verify) the client is refused at the TLS
handshake (CERTIFICATE_VERIFY_FAILED / TLSV13_ALERT_CERTIFICATE_REQUIRED)
so ``/mcp/health`` reported 503 ``opa_unreachable`` even when OPA was
genuinely healthy and every other broker->OPA call site (which already
used ``_make_opa_http_client``) was succeeding.

Fix under test (Tom, 2026-07-31): ``_opa_health_check`` now builds its
client via ``yashigani.mcp._opa._make_opa_http_client`` — the SAME single
client-construction path ``McpBroker.opa_health()`` uses (mesh
ServiceIdentity mTLS primary, YASHIGANI_CA_CERT / system-trust fallback).
No new TLS config path introduced.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestOpaHealthCheckUsesMeshClient:
    @pytest.mark.asyncio
    async def test_opa_health_check_calls_make_opa_http_client(self):
        """_opa_health_check must build its httpx client via
        _make_opa_http_client (the mesh-mTLS-aware factory), not a bare
        httpx.AsyncClient(). Patches the factory at its point of use inside
        mcp/router.py."""
        from yashigani.mcp import router as router_mod

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            router_mod, "_make_opa_http_client", return_value=cm
        ) as mock_factory:
            result = await router_mod._opa_health_check("https://policy:8181")

        assert result is True
        mock_factory.assert_called_once_with(timeout=2.0)
        mock_client.get.assert_awaited_once_with("https://policy:8181/health")

    @pytest.mark.asyncio
    async def test_opa_health_check_is_not_bare_httpx_client(self):
        """Regression guard: if the mesh-mTLS client is unavailable (e.g. no
        ServiceIdentity secrets in this process) _make_opa_http_client itself
        falls back to a CA-trust/system-trust httpx.AsyncClient — but
        _opa_health_check must delegate that decision to the shared factory
        rather than constructing httpx.AsyncClient() directly with no CA
        config at all. Verify the router module no longer references a bare
        httpx.AsyncClient call inside _opa_health_check's source."""
        import ast
        import inspect
        import textwrap

        from yashigani.mcp import router as router_mod

        src = inspect.getsource(router_mod._opa_health_check)
        tree = ast.parse(textwrap.dedent(src))
        func_node = tree.body[0]
        # Strip the docstring (first statement, an ast.Expr wrapping a
        # constant string) before scanning for a bare httpx.AsyncClient
        # call in the actual executable body.
        body = func_node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant
        ):
            body = body[1:]
        body_src = "\n".join(ast.unparse(stmt) for stmt in body)

        assert "_make_opa_http_client" in body_src
        assert "httpx.AsyncClient" not in body_src

    @pytest.mark.asyncio
    async def test_opa_health_check_false_on_tls_handshake_failure(self):
        """A mesh-mTLS OPA refusing an identity-less client at the TLS
        handshake must surface as opa_ok=False (fail-closed), not raise."""
        import httpx as httpx_mod

        from yashigani.mcp import router as router_mod

        with patch.object(
            router_mod,
            "_make_opa_http_client",
            side_effect=httpx_mod.ConnectError("TLSV13_ALERT_CERTIFICATE_REQUIRED"),
        ):
            result = await router_mod._opa_health_check("https://policy:8181")

        assert result is False
