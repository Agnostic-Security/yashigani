# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — mesh-aware Ollama transport (v4.1 Phase 1c, Task C / LAURA-I1-01).

Scheme rule under test:
  * https:// (the Caddy :11435 Ollama front) → internal mesh mTLS client
    (yashigani.pki.client — presents this service's leaf, verifies the
    internal CA).  Without this the front fails CLOSED at the handshake.
  * http://  (legacy single-bridge / dev) → plain httpx client, behaviour
    unchanged.
Consumers wired through this module: inspection.classifier,
inspection.backends.ollama, optimization.sensitivity_classifier,
backoffice.routes.models.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from yashigani.inspection import _ollama_transport as tx


class TestSchemeRouting:
    def test_http_url_uses_plain_sync_client(self):
        client = tx.ollama_sync_client("http://ollama:11434")
        try:
            assert isinstance(client, httpx.Client)
        finally:
            client.close()

    @pytest.mark.asyncio
    async def test_http_url_uses_plain_async_client(self):
        client = tx.ollama_async_client("http://ollama:11434")
        try:
            assert isinstance(client, httpx.AsyncClient)
        finally:
            await client.aclose()

    def test_https_url_uses_internal_mesh_sync_client(self):
        sentinel = MagicMock(spec=httpx.Client)
        with patch(
            "yashigani.pki.client.internal_httpx_sync_client",
            return_value=sentinel,
        ) as mesh:
            client = tx.ollama_sync_client("https://caddy:11435/ollama")
        mesh.assert_called_once()
        assert client is sentinel

    @pytest.mark.asyncio
    async def test_https_url_uses_internal_mesh_async_client(self):
        sentinel = MagicMock(spec=httpx.AsyncClient)
        with patch(
            "yashigani.pki.client.internal_httpx_client",
            return_value=sentinel,
        ) as mesh:
            client = tx.ollama_async_client("https://caddy:11435/ollama")
        mesh.assert_called_once()
        assert client is sentinel

    def test_scheme_detection_is_case_insensitive(self):
        assert tx._is_mesh_url("HTTPS://caddy:11435/ollama")
        assert not tx._is_mesh_url("http://ollama:11434")


class TestHelpers:
    def test_post_json_raises_on_http_error(self):
        fake = MagicMock()
        fake.__enter__ = MagicMock(return_value=fake)
        fake.__exit__ = MagicMock(return_value=False)
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "boom", request=MagicMock(), response=MagicMock(),
        )
        fake.post.return_value = resp
        with patch.object(tx, "ollama_sync_client", return_value=fake):
            with pytest.raises(httpx.HTTPError):
                tx.ollama_post_json("http://ollama:11434", "/api/chat", {})

    def test_get_json_returns_none_on_error(self):
        with patch.object(tx, "ollama_sync_client", side_effect=RuntimeError("x")):
            assert tx.ollama_get_json("http://ollama:11434", "/api/tags") is None

    def test_get_json_returns_body_on_200(self):
        fake = MagicMock()
        fake.__enter__ = MagicMock(return_value=fake)
        fake.__exit__ = MagicMock(return_value=False)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"models": []}
        fake.get.return_value = resp
        with patch.object(tx, "ollama_sync_client", return_value=fake):
            assert tx.ollama_get_json("http://o:1", "/api/tags") == {"models": []}
