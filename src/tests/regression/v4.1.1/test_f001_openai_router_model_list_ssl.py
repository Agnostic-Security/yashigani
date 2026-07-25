"""
Regression tests — F-001 (model-list seam): list_models Ollama fetch TLS.

What this tests:
  A. list_models uses ollama_async_client (mesh-aware transport), NOT bare
     httpx.AsyncClient, for the /api/tags Ollama fetch.
     Regression: the old code did
         import httpx
         async with httpx.AsyncClient(timeout=5.0) as client:
             resp = await client.get(f"{_state.ollama_url}/api/tags")
     which has no SSL context and raises CERTIFICATE_VERIFY_FAILED when
     ollama_url is https://caddy:11435/ollama (Mac Metal + any mTLS-Ollama
     deployment).

  B. For https ollama_url the transport receives the correct base_url so
     ollama_async_client can select the PKI-verified client.

  C. For plain http://ollama:11434 (Linux container path) the http fallback
     in ollama_async_client is unaffected — models still populate correctly.

  D. When the Ollama fetch fails (connection refused, timeout, cert error),
     the exception is swallowed and list_models still returns a model list
     with zero Ollama entries (pre-existing best-effort semantics must not
     regress).

Last updated: 2026-07-12T00:00:00+00:00
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tags_response(models: list[str]) -> MagicMock:
    """Build a mock httpx Response for Ollama /api/tags (200 OK)."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "models": [{"name": m} for m in models]
    })
    return resp


def _make_async_client_cm(resp: MagicMock) -> MagicMock:
    """Async context manager that yields a mock httpx client returning *resp*."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=resp)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_mock_state(ollama_url: str) -> MagicMock:
    state = MagicMock()
    state.ollama_url = ollama_url
    state.identity_registry = None   # no service identity models
    state.agent_registry = None      # no agent models
    state.audit_writer = None        # skip audit write
    state.opa_url = "http://opa:8181"  # non-empty so _opa_models_check doesn't short-circuit
    return state


def _mock_identity() -> dict:
    return {
        "identity_id": "idnt_test_human",
        "kind": "HUMAN",
        "groups": ["admin"],
    }


# ---------------------------------------------------------------------------
# Shared patch context: wires auth + OPA into allow/full so the Ollama fetch
# branch is always reached in each test.
# ---------------------------------------------------------------------------

def _list_models_patches(ollama_url: str, mock_ollama_cm: MagicMock):
    """
    Return the patch stack needed to exercise the Ollama fetch branch of
    list_models without a live gateway/OPA/identity-registry.
    """
    mock_ollama_async_client = MagicMock(return_value=mock_ollama_cm)
    return (
        mock_ollama_async_client,
        [
            patch(
                "yashigani.inspection._ollama_transport.ollama_async_client",
                mock_ollama_async_client,
            ),
            patch(
                "yashigani.gateway.openai_router._state",
                _make_mock_state(ollama_url),
            ),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=_mock_identity()),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_models_check",
                AsyncMock(return_value={"allow": True, "filter": "full", "reason": "ok"}),
            ),
            patch(
                "yashigani.gateway.openai_router._service_account_full_list_enabled",
                MagicMock(return_value=False),
            ),
        ],
    )


def _make_mock_request() -> MagicMock:
    from fastapi import Request
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {}
    mock_request.state = MagicMock()
    mock_request.state.ysg_principal = None
    return mock_request


# ---------------------------------------------------------------------------
# A + B. https ollama_url routes through ollama_async_client
# ---------------------------------------------------------------------------

class TestListModelsHttpsOllamaUrl:
    """list_models must use ollama_async_client for https://caddy:11435/ollama."""

    async def test_https_ollama_url_routes_through_ollama_async_client(self):
        """
        When _state.ollama_url is https://caddy:11435/ollama, list_models MUST
        call ollama_async_client (not bare httpx.AsyncClient directly).

        Regression: the old code imported httpx inside the try block and created
        a bare AsyncClient with no SSL context.  ollama_async_client() selects
        internal_httpx_client() for https:// URLs, which loads the mesh PKI.
        """
        https_url = "https://caddy:11435/ollama"
        mock_tags_resp = _make_tags_response(["llama3.2:3b", "nomic-embed-text"])
        mock_cm = _make_async_client_cm(mock_tags_resp)

        mock_ollama_async_client, patches = _list_models_patches(https_url, mock_cm)

        import contextlib
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import list_models
            result = await list_models(_make_mock_request())

        # ollama_async_client MUST have been called (not bare httpx.AsyncClient).
        mock_ollama_async_client.assert_called_once(), (
            "list_models must call ollama_async_client, not bare httpx.AsyncClient"
        )

        # First positional arg must be the ollama_url so the scheme
        # selection (http vs https) inside ollama_async_client works.
        actual_url = mock_ollama_async_client.call_args[0][0]
        assert actual_url == https_url, (
            f"ollama_async_client must receive ollama_url={https_url!r}; "
            f"got {actual_url!r}"
        )

        # Models from the mock response must appear in result.
        model_ids = {m.id for m in result.data}
        assert "llama3.2:3b" in model_ids, (
            f"Expected llama3.2:3b in model list; got {model_ids}"
        )

    async def test_https_url_passes_correct_timeout(self):
        """ollama_async_client must be called with timeout=5.0 for the model-list fetch."""
        https_url = "https://caddy:11435/ollama"
        mock_tags_resp = _make_tags_response(["qwen2.5:3b"])
        mock_cm = _make_async_client_cm(mock_tags_resp)

        mock_ollama_async_client, patches = _list_models_patches(https_url, mock_cm)

        import contextlib
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import list_models
            await list_models(_make_mock_request())

        timeout = mock_ollama_async_client.call_args[1].get("timeout")
        assert timeout == 5.0, (
            f"model-list fetch must use timeout=5.0; got {timeout!r}"
        )


# ---------------------------------------------------------------------------
# C. http URL — plain fallback still works
# ---------------------------------------------------------------------------

class TestListModelsHttpOllamaUrl:
    """Plain http://ollama:11434 must still populate the model list after the fix."""

    async def test_http_ollama_url_still_populates_models(self):
        """
        ollama_async_client falls through to a plain httpx.AsyncClient for http://
        URLs.  list_models must still call ollama_async_client (not bare httpx)
        and the model list must populate.
        """
        http_url = "http://ollama:11434"
        mock_tags_resp = _make_tags_response(["phi4:latest"])
        mock_cm = _make_async_client_cm(mock_tags_resp)

        mock_ollama_async_client, patches = _list_models_patches(http_url, mock_cm)

        import contextlib
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import list_models
            result = await list_models(_make_mock_request())

        # Must still route through ollama_async_client (not bypass it).
        mock_ollama_async_client.assert_called_once()
        assert mock_ollama_async_client.call_args[0][0] == http_url

        # Model from mock response must appear.
        model_ids = {m.id for m in result.data}
        assert "phi4:latest" in model_ids


# ---------------------------------------------------------------------------
# D. Fetch failure — exception is swallowed; partial results still returned
# ---------------------------------------------------------------------------

class TestListModelsOllamaFetchFailure:
    """When the Ollama /api/tags fetch fails, list_models must not raise."""

    async def test_connection_error_is_swallowed(self):
        """
        CERTIFICATE_VERIFY_FAILED, connection refused, or any other exception
        from the Ollama fetch is caught by the except clause.  list_models must
        return a result object with zero Ollama-owned models rather than
        propagating the exception as a 500.

        This is the pre-existing best-effort semantics and must not regress.
        """
        import httpx

        # Context manager that raises on __aenter__
        failing_cm = MagicMock()
        failing_cm.__aenter__ = AsyncMock(
            side_effect=httpx.ConnectError("CERTIFICATE_VERIFY_FAILED")
        )
        failing_cm.__aexit__ = AsyncMock(return_value=False)

        mock_ollama_async_client, patches = _list_models_patches(
            "https://caddy:11435/ollama", failing_cm
        )

        import contextlib
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import list_models
            # Must not raise — exception must be swallowed by the except clause.
            result = await list_models(_make_mock_request())

        # Result is a valid ModelList; Ollama models are absent but no 500.
        assert hasattr(result, "data"), "list_models must return a ModelList-shaped object"
        ollama_model_ids = [
            m.id for m in result.data
            if "ollama (local)" in getattr(m, "owned_by", "")
        ]
        assert ollama_model_ids == [], (
            f"Ollama models must be absent on fetch failure; got {ollama_model_ids}"
        )
