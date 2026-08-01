"""
Regression test -- v4.1.2 YSG-RISK-191:

``GET /admin/budget/models/local-inventory`` (routes/budget.py,
``get_local_model_inventory``) hardcoded::

    ollama_base = os.environ.get("YASHIGANI_OLLAMA_URL", "http://ollama:11434")
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{ollama_base}/api/tags")

Two bugs stacked:

  1. Wrong env var. No deployment config (docker-compose.yml, helm
     templates, gateway/backoffice entrypoints) ever sets
     ``YASHIGANI_OLLAMA_URL`` -- the real mesh-wired variable is
     ``OLLAMA_BASE_URL``. The route silently fell back to the hardcoded
     literal on every real deployment.

  2. Bare ``httpx.AsyncClient``, not the mesh-mTLS-aware transport. Per
     ``inspection/_ollama_transport.py`` (the documented single transport for
     every ``OLLAMA_BASE_URL`` consumer -- see F-001, v4.1.1), Ollama has
     been reachable ONLY via the Caddy mesh front
     ``https://caddy:11435/ollama`` since v4.1 Phase 1b-ii. A bare httpx
     client has no SSL context and fails
     ``CERTIFICATE_VERIFY_FAILED``/connect-refused against that front --
     hence the 502 (``ollama_unavailable``) even when Ollama itself is
     healthy behind the mesh.

Fix mirrors ``routes/models.py``'s existing, correct ``_ollama_base()`` +
``ollama_async_client()`` pattern: chain
``YASHIGANI_OLLAMA_URL -> OLLAMA_BASE_URL -> "http://ollama:11434"`` and
route the ``/api/tags`` fetch through ``ollama_async_client`` (mesh-mTLS for
https://, plain httpx for http://, unchanged from the F-001 test suite's
existing coverage of that helper).
"""
from __future__ import annotations

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_tags_response(models: list[str]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={
        "models": [
            {
                "name": m,
                "size": 4 * 1024 * 1024 * 1024,
                "details": {"parameter_size": "8B", "quantization_level": "Q4_K_M", "family": "llama"},
                "modified_at": "2026-07-01T00:00:00Z",
            }
            for m in models
        ]
    })
    return resp


def _make_async_client_cm(resp: MagicMock) -> MagicMock:
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


class TestLocalInventoryResolvesMeshEndpoint:
    """OLLAMA_BASE_URL (the real deployment-wired var) must be honoured, and
    the fetch must go through the mesh-aware transport -- not bare httpx."""

    async def test_https_mesh_url_from_ollama_base_url_env(self, monkeypatch):
        """Regression for bug 1: previously OLLAMA_BASE_URL was never read at
        all, so this exact deployment config (only OLLAMA_BASE_URL set, no
        YASHIGANI_OLLAMA_URL) silently fell back to http://ollama:11434."""
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        mock_resp = _make_tags_response(["llama3.2:3b"])
        mock_cm = _make_async_client_cm(mock_resp)
        mock_ollama_async_client = MagicMock(return_value=mock_cm)

        with patch(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            mock_ollama_async_client,
        ):
            from yashigani.backoffice.routes.budget import get_local_model_inventory
            result = await get_local_model_inventory()

        assert result["ollama_url"] == "https://caddy:11435/ollama", (
            f"expected the OLLAMA_BASE_URL mesh front to be resolved; got {result['ollama_url']!r}"
        )
        mock_ollama_async_client.assert_called_once()
        assert mock_ollama_async_client.call_args[0][0] == "https://caddy:11435/ollama", (
            "ollama_async_client must receive the resolved mesh URL as its base_url arg "
            "so it selects the mTLS-verified client for https://"
        )
        model_names = {m["name"] for m in result["models"]}
        assert "llama3.2:3b" in model_names

    async def test_uses_mesh_aware_transport_not_bare_httpx(self, monkeypatch):
        """Regression for bug 2: the route must call ollama_async_client, and
        must NOT construct a bare httpx.AsyncClient directly for the fetch."""
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        mock_resp = _make_tags_response([])
        mock_cm = _make_async_client_cm(mock_resp)
        mock_ollama_async_client = MagicMock(return_value=mock_cm)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.inspection._ollama_transport.ollama_async_client",
                mock_ollama_async_client,
            ))
            bare_httpx_client = stack.enter_context(
                patch("yashigani.backoffice.routes.budget.httpx.AsyncClient")
            )
            from yashigani.backoffice.routes.budget import get_local_model_inventory
            await get_local_model_inventory()

        mock_ollama_async_client.assert_called_once()
        bare_httpx_client.assert_not_called(), (
            "bare httpx.AsyncClient must not be used for the /api/tags fetch -- "
            "it has no mesh SSL context and fails CERTIFICATE_VERIFY_FAILED "
            "against https://caddy:11435/ollama"
        )

    async def test_explicit_override_still_wins_over_ollama_base_url(self, monkeypatch):
        """YASHIGANI_OLLAMA_URL remains a valid explicit override (matches
        routes/models.py's _ollama_base() precedence) -- e.g. an operator
        pointing at a non-standard Ollama endpoint for this one panel."""
        monkeypatch.setenv("YASHIGANI_OLLAMA_URL", "http://ollama-override:11434")
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        mock_resp = _make_tags_response([])
        mock_cm = _make_async_client_cm(mock_resp)
        mock_ollama_async_client = MagicMock(return_value=mock_cm)

        with patch(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            mock_ollama_async_client,
        ):
            from yashigani.backoffice.routes.budget import get_local_model_inventory
            result = await get_local_model_inventory()

        assert result["ollama_url"] == "http://ollama-override:11434"

    async def test_no_env_configured_falls_back_to_dev_default(self, monkeypatch):
        """Neither var set -> the legacy hardcoded http://ollama:11434 default
        (community/dev single-bridge deploy) must still work unchanged."""
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)

        mock_resp = _make_tags_response(["phi4:latest"])
        mock_cm = _make_async_client_cm(mock_resp)
        mock_ollama_async_client = MagicMock(return_value=mock_cm)

        with patch(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            mock_ollama_async_client,
        ):
            from yashigani.backoffice.routes.budget import get_local_model_inventory
            result = await get_local_model_inventory()

        assert result["ollama_url"] == "http://ollama:11434"
        assert mock_ollama_async_client.call_args[0][0] == "http://ollama:11434"


class TestLocalInventoryFetchFailureStillHandledCleanly:
    """A genuinely unreachable Ollama (not a mesh-bypass artefact) must still
    surface a clean 502/504, not an unhandled 500."""

    async def test_connect_error_returns_502_ollama_unavailable(self, monkeypatch):
        import httpx
        from fastapi import HTTPException

        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        failing_cm = MagicMock()
        failing_cm.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        failing_cm.__aexit__ = AsyncMock(return_value=False)
        mock_ollama_async_client = MagicMock(return_value=failing_cm)

        with patch(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            mock_ollama_async_client,
        ):
            from yashigani.backoffice.routes.budget import get_local_model_inventory
            with pytest.raises(HTTPException) as exc_info:
                await get_local_model_inventory()

        assert exc_info.value.status_code == 502
        assert exc_info.value.detail["error"] == "ollama_unavailable"
