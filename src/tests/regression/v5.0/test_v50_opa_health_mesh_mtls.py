# Last updated: 2026-07-28T00:00:00+00:00
"""
Regression — mcp/broker.py:1778 ``McpBroker.opa_health()`` used a bare,
identity-less ``httpx.AsyncClient()`` — unlike EVERY other broker→OPA call
site (``query_mcp_decision``, ``query_filesystem_tool_allowed``,
``query_git_tool_allowed``, ``query_mcp_response_decision``), which all go
through ``mcp/_opa.py::_make_opa_http_client()`` — the SINGLE place that
client is built with the gateway's mesh ServiceIdentity (mTLS leaf + CA
trust; see FIX-MCP-001, ``_opa.py:89-150``). OPA sits behind the service
mesh and requires a client leaf at the TLS handshake
(``require_and_verify``). A bare, identity-less client is refused at the
handshake — ``TLSV13_ALERT_CERTIFICATE_REQUIRED`` — before any HTTP
exchange, so ``GET /mcp/health`` reported ``opa_unreachable`` / 503 even
when OPA was healthy and every other broker→OPA call (the real
enforcement path) was succeeding. This made the health probe an
unreliable (falsely negative) signal for operators and monitoring.

Fix under test (Tom, 2026-07-28): ``opa_health()`` now uses
``_make_opa_http_client()`` — the SAME mesh-mTLS client every other broker
OPA call site uses. The bare ``import httpx`` at the top of broker.py
(previously used ONLY by ``opa_health()``) has also been removed —
``yashigani.mcp.broker`` no longer has an ``httpx`` attribute at all,
closing off any accidental re-introduction of a bare client in this
module.

Landed alongside LAURA-V50-016 (same root sweep: broker→OPA/Redis wiring
must reuse the gateway's shared, correctly-authenticated construction
helpers instead of re-deriving connections independently per call site).
"""
from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1


def _p384_key_pem_b64() -> str:
    key = ec.generate_private_key(SECP384R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


def _make_broker():
    from yashigani.mcp._jwt import McpJwtIssuer, McpJwtVerifier
    from yashigani.mcp._nonce import InMemoryNonceStore
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig

    key = ec.generate_private_key(SECP384R1())
    issuer = McpJwtIssuer(
        tenant_id="tenant1", private_key=key, key_generated_at=1748476800,
        chain_max_depth=3,
    )
    verifier = McpJwtVerifier.from_issuer(issuer)
    nonce_store = InMemoryNonceStore()
    config = McpBrokerConfig(
        opa_url="https://policy:8181",
        tenant_id="tenant1",
        issuer=issuer,
        verifier=verifier,
        nonce_store=nonce_store,
        audit_writer=None,  # test mode
    )
    return McpBroker(config)


class TestOpaHealthUsesMeshMtlsClient:
    def test_bare_httpx_import_removed_from_broker_module(self):
        """Structural guard: broker.py must not re-introduce a module-level
        `import httpx` — every httpx client in this module must come from
        `_make_opa_http_client` (or a per-tenant pool), not a bare import."""
        import yashigani.mcp.broker as broker_mod

        assert not hasattr(broker_mod, "httpx"), (
            "yashigani.mcp.broker imports httpx directly again — this is "
            "the exact regression that produced an identity-less OPA "
            "client in opa_health(). Route through _make_opa_http_client "
            "instead."
        )

    @pytest.mark.asyncio
    async def test_opa_health_routes_through_shared_mesh_mtls_factory(self):
        """opa_health() must call _make_opa_http_client (the mesh-mTLS
        factory shared by every other broker->OPA call site), not build its
        own client."""
        broker = _make_broker()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        factory_mock = MagicMock(return_value=cm)
        with patch("yashigani.mcp.broker._make_opa_http_client", factory_mock):
            result = await broker.opa_health()

        assert result is True
        assert factory_mock.called, (
            "opa_health() did not go through _make_opa_http_client — the "
            "mesh-mTLS OPA client factory every other call site uses."
        )
        mock_client.get.assert_awaited_once_with("https://policy:8181/health")

    @pytest.mark.asyncio
    async def test_opa_health_false_on_non_200(self):
        broker = _make_broker()

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("yashigani.mcp.broker._make_opa_http_client", return_value=cm):
            result = await broker.opa_health()

        assert result is False

    @pytest.mark.asyncio
    async def test_opa_health_false_on_client_exception(self):
        """Fail-closed: any exception constructing/using the client -> False,
        never a raised exception out of opa_health()."""
        broker = _make_broker()

        with patch(
            "yashigani.mcp.broker._make_opa_http_client",
            side_effect=RuntimeError("mesh identity unavailable"),
        ):
            result = await broker.opa_health()

        assert result is False
