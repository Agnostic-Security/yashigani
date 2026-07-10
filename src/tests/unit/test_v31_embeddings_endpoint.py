"""
Unit tests: POST /v1/embeddings endpoint (3.1).

Covers the four key requirements from the brief:

  EMBED-001 — Ollama happy path: input → Ollama /api/embed, returns OpenAI
              embeddings response shape.
  EMBED-002 — Sensitive input + cloud route → refused with
              routing_unsafe_sensitive_to_cloud (the key security assertion).
  EMBED-003 — Cloud provider with no embeddings API (Anthropic) → falls back
              to Ollama embedder and succeeds.
  EMBED-004 — OPA deny → fail-closed (403, not 200).
  EMBED-005 — Auth missing → 401, same error contract as chat.

All tests run without a live stack (Ollama and OPA are mocked via httpx or
unittest.mock).  No /tmp, no external network calls.

Last updated: 2026-06-19T00:00:00+00:00
"""
from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Environment bootstrap — must happen BEFORE any yashigani import.
# The conftest.py sets YASHIGANI_ENV, YASHIGANI_INTERNAL_BEARER, and
# YASHIGANI_OPA_OPTIONAL; these are already in place when this module loads.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_router_state():
    """Reset openai_router _state to a clean baseline for each test."""
    from yashigani.gateway import openai_router as _m
    _m._state.identity_registry = None
    _m._state.sensitivity_classifier = None
    _m._state.optimization_engine = None
    _m._state.complexity_scorer = None
    _m._state.budget_enforcer = None
    _m._state.audit_writer = None
    _m._state.opa_url = ""        # OPA optional in tests (YASHIGANI_OPA_OPTIONAL=true)
    _m._state.ollama_url = "http://ollama:11434"
    _m._state.default_model = "nomic-embed-text"
    _m._state._cloud_key_cache = {}


def _active_identity(identity_id: str = "alice") -> dict:
    """Return a minimal active identity dict."""
    return {
        "identity_id": identity_id,
        "status": "active",
        "kind": "human",
        "groups": [],
        "allowed_models": [],
        "sensitivity_ceiling": "RESTRICTED",
    }


def _make_internal_bearer_request(body: dict | None = None) -> Any:
    """Build a Starlette Request that passes identity resolution using the
    internal bearer (avoids needing a live identity registry)."""
    from starlette.requests import Request

    bearer = os.environ.get("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-unit-tests")
    headers = [
        (b"authorization", f"Bearer {bearer}".encode()),
        (b"content-type", b"application/json"),
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/embeddings",
        "query_string": b"",
        "headers": headers,
    }
    return Request(scope)


def _make_anon_request() -> Any:
    """Build a Starlette Request with no auth headers (anonymous caller)."""
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/embeddings",
        "query_string": b"",
        "headers": [],
    }
    return Request(scope)


def _make_ollama_embed_mock(embeddings: list[list[float]], model: str = "nomic-embed-text"):
    """Return an async context manager mock for httpx.AsyncClient that returns
    Ollama /api/embed response shape."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": model,
        "embeddings": embeddings,
    }
    mock_resp.text = ""

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, mock_client


def _make_opa_allow_mock(allow: bool = True, reason: str = "ok"):
    """Patch _opa_v1_check to return a canned decision."""
    decision = {
        "allow": allow,
        "reason": reason,
        "model_allowed": True,
        "routing_safe": allow,
        "sensitivity_allowed": True,
    }
    return patch(
        "yashigani.gateway.openai_router._opa_v1_check",
        new=AsyncMock(return_value=decision),
    )


# ---------------------------------------------------------------------------
# EMBED-001 — Ollama happy path
# ---------------------------------------------------------------------------

class TestOllamaHappyPath:
    """EMBED-001: local Ollama route → returns OpenAI embeddings shape."""

    @pytest.mark.asyncio
    async def test_single_input_returns_openai_shape(self):
        """Single string input → embedding in OpenAI list/data/embedding shape."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="hello world")

        expected_vector = [0.1, 0.2, 0.3, 0.4]
        cm, mock_client = _make_ollama_embed_mock([expected_vector])

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                resp = await create_embeddings(body, req)

        # resp is a JSONResponse
        data = json.loads(resp.body)

        assert data["object"] == "list", f"Expected 'list', got {data['object']!r}"
        assert len(data["data"]) == 1, f"Expected 1 embedding, got {len(data['data'])}"
        emb = data["data"][0]
        assert emb["object"] == "embedding"
        assert emb["embedding"] == expected_vector
        assert emb["index"] == 0
        assert "model" in data
        assert "usage" in data
        assert "prompt_tokens" in data["usage"]

    @pytest.mark.asyncio
    async def test_list_input_returns_multiple_embeddings(self):
        """List input with 2 items → 2 embeddings in response."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(
            model="nomic-embed-text",
            input=["first sentence", "second sentence"],
        )

        vectors = [[0.1, 0.2], [0.3, 0.4]]
        cm, _ = _make_ollama_embed_mock(vectors)

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                resp = await create_embeddings(body, req)

        data = json.loads(resp.body)
        assert len(data["data"]) == 2, f"Expected 2 embeddings, got {len(data['data'])}"
        assert data["data"][0]["index"] == 0
        assert data["data"][1]["index"] == 1

    @pytest.mark.asyncio
    async def test_ollama_url_used(self):
        """Ollama /api/embed is called on the configured ollama_url."""
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()
        _m._state.ollama_url = "http://ollama-test:11434"

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="test")

        cm, mock_client = _make_ollama_embed_mock([[0.5, 0.6]])

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                await create_embeddings(body, req)

        # Verify the POST was called with the correct URL
        call_args = mock_client.post.call_args
        assert call_args is not None
        url_called = call_args[0][0] if call_args[0] else call_args.kwargs.get("url", "")
        assert "ollama-test:11434" in url_called, (
            f"Expected ollama-test:11434 in URL, got {url_called!r}"
        )
        assert "/api/embed" in url_called, (
            f"Expected /api/embed in URL, got {url_called!r}"
        )

    @pytest.mark.asyncio
    async def test_response_headers_set(self):
        """Response carries X-Yashigani-Routed-Via: ollama header."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="hello")

        cm, _ = _make_ollama_embed_mock([[0.1]])

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                resp = await create_embeddings(body, req)

        assert resp.headers.get("x-yashigani-routed-via") == "ollama", (
            f"Expected routed-via=ollama, got {resp.headers.get('x-yashigani-routed-via')!r}"
        )
        assert "x-yashigani-request-id" in resp.headers


# ---------------------------------------------------------------------------
# EMBED-002 — Sensitive input + cloud route → routing_unsafe_sensitive_to_cloud
# ---------------------------------------------------------------------------

class TestSensitiveInputCloudRefused:
    """EMBED-002: sensitive input + cloud provider → refused with
    routing_unsafe_sensitive_to_cloud error code."""

    @pytest.mark.asyncio
    async def test_restricted_input_cloud_route_refused(self):
        """SSN in input + cloud-routed model → 403 routing_unsafe_sensitive_to_cloud."""
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier

        _reset_router_state()
        # Wire the real classifier so SSN triggers RESTRICTED
        _m._state.sensitivity_classifier = SensitivityClassifier()

        req = _make_internal_bearer_request()
        # SSN triggers RESTRICTED sensitivity
        body = EmbeddingRequest(
            model="text-embedding-3-small",
            input="My SSN is 123-45-6789",
        )

        # OPA says allow (routing_safe=False will be caught by the belt-and-braces
        # gate in the handler, not OPA). We simulate the provider being cloud.
        opa_allow = {
            "allow": True,
            "reason": "ok",
            "model_allowed": True,
            "routing_safe": False,  # OPA sees it as unsafe too
            "sensitivity_allowed": True,
        }

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_allow),
        ):
            # Simulate optimization engine picking openai (cloud)
            mock_decision = MagicMock()
            mock_decision.provider = "openai"
            mock_decision.model = "text-embedding-3-small"
            mock_decision.rule = "cloud_preferred"
            mock_decision.reason = "low_sensitivity_allows_cloud"

            mock_engine = MagicMock()
            mock_engine.route.return_value = mock_decision

            mock_scorer = MagicMock()
            mock_scorer.score.return_value = MagicMock(
                level=MagicMock(value="MEDIUM"), token_count=10,
                heuristic_score=0.0, reasons=[]
            )

            _m._state.optimization_engine = mock_engine
            _m._state.complexity_scorer = mock_scorer

            resp = await create_embeddings(body, req)

        # Must get 403
        assert resp.status_code == 403, (
            f"Expected 403, got {resp.status_code}. Body: {resp.body}"
        )
        data = json.loads(resp.body)
        assert data["error"]["code"] == "routing_unsafe_sensitive_to_cloud", (
            f"Expected routing_unsafe_sensitive_to_cloud, got {data['error']['code']!r}"
        )

    @pytest.mark.asyncio
    async def test_confidential_input_cloud_route_refused(self):
        """Email address in input + cloud provider → 403."""
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier

        _reset_router_state()
        _m._state.sensitivity_classifier = SensitivityClassifier()

        req = _make_internal_bearer_request()
        # Email triggers CONFIDENTIAL sensitivity
        body = EmbeddingRequest(
            model="text-embedding-3-small",
            input="Contact alice@secret-corp.example.com about the project",
        )

        opa_allow = {
            "allow": True, "reason": "ok",
            "model_allowed": True, "routing_safe": False, "sensitivity_allowed": True,
        }

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_allow),
        ):
            mock_decision = MagicMock()
            mock_decision.provider = "openai"
            mock_decision.model = "text-embedding-3-small"
            mock_decision.rule = "cloud"
            mock_decision.reason = "routed_cloud"

            mock_engine = MagicMock()
            mock_engine.route.return_value = mock_decision
            mock_scorer = MagicMock()
            _m._state.optimization_engine = mock_engine
            _m._state.complexity_scorer = mock_scorer

            resp = await create_embeddings(body, req)

        assert resp.status_code == 403
        data = json.loads(resp.body)
        assert data["error"]["code"] == "routing_unsafe_sensitive_to_cloud"

    @pytest.mark.asyncio
    async def test_public_input_cloud_route_allowed(self):
        """Non-sensitive input + cloud route → NOT refused (200 from mock)."""
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier

        _reset_router_state()
        _m._state.sensitivity_classifier = SensitivityClassifier()
        _m._state._cloud_key_cache = {}

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(
            model="text-embedding-3-small",
            input="The weather is nice today",
        )

        opa_allow = {
            "allow": True, "reason": "ok",
            "model_allowed": True, "routing_safe": True, "sensitivity_allowed": True,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [{"object": "embedding", "embedding": [0.1, 0.2, 0.3], "index": 0}],
            "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": 5, "total_tokens": 5},
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_allow),
        ):
            # Force provider to openai via env-based key mock
            with patch(
                "yashigani.gateway.openai_router._get_cloud_api_key",
                return_value="sk-test-key",
            ):
                mock_decision = MagicMock()
                mock_decision.provider = "openai"
                mock_decision.model = "text-embedding-3-small"
                mock_decision.rule = "cloud"
                mock_decision.reason = "routed_cloud"

                mock_engine = MagicMock()
                mock_engine.route.return_value = mock_decision
                mock_scorer = MagicMock()
                _m._state.optimization_engine = mock_engine
                _m._state.complexity_scorer = mock_scorer

                with patch("httpx.AsyncClient", return_value=cm):
                    resp = await create_embeddings(body, req)

        assert resp.status_code == 200, (
            f"Expected 200 for public input + cloud, got {resp.status_code}. Body: {resp.body}"
        )


# ---------------------------------------------------------------------------
# EMBED-003 — Anthropic (no embeddings API) → falls back to Ollama
# ---------------------------------------------------------------------------

class TestAnthropicFallsBackToOllama:
    """EMBED-003: cloud provider with no embeddings API falls back to Ollama."""

    @pytest.mark.asyncio
    async def test_anthropic_provider_falls_back_to_ollama(self):
        """When optimization engine picks Anthropic, handler falls back to Ollama."""
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(
            model="claude-haiku-4-5",
            input="summarise this document",
        )

        opa_allow = {
            "allow": True, "reason": "ok",
            "model_allowed": True, "routing_safe": True, "sensitivity_allowed": True,
        }

        ollama_resp = MagicMock()
        ollama_resp.status_code = 200
        ollama_resp.json.return_value = {
            "model": "nomic-embed-text",
            "embeddings": [[0.9, 0.8, 0.7]],
        }
        ollama_resp.text = ""

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=ollama_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_allow),
        ):
            # Engine decides Anthropic
            mock_decision = MagicMock()
            mock_decision.provider = "anthropic"
            mock_decision.model = "claude-haiku-4-5"
            mock_decision.rule = "cloud"
            mock_decision.reason = "anthropic"

            mock_engine = MagicMock()
            mock_engine.route.return_value = mock_decision
            mock_scorer = MagicMock()
            _m._state.optimization_engine = mock_engine
            _m._state.complexity_scorer = mock_scorer

            with patch("httpx.AsyncClient", return_value=cm):
                resp = await create_embeddings(body, req)

        assert resp.status_code == 200, (
            f"Expected 200 (Ollama fallback), got {resp.status_code}. Body: {resp.body}"
        )
        data = json.loads(resp.body)
        assert len(data["data"]) == 1
        assert data["data"][0]["embedding"] == [0.9, 0.8, 0.7]

        # Verify the call went to Ollama /api/embed, NOT to anthropic.com
        call_args = mock_client.post.call_args
        url_called = call_args[0][0] if call_args[0] else ""
        assert "anthropic" not in url_called.lower(), (
            f"Should NOT have called Anthropic endpoint, called: {url_called!r}"
        )
        assert "/api/embed" in url_called, (
            f"Expected Ollama /api/embed, got: {url_called!r}"
        )

    @pytest.mark.asyncio
    async def test_get_cloud_embedding_model_anthropic_returns_none(self):
        """_get_cloud_embedding_model('anthropic') returns None (no embeddings API)."""
        from yashigani.gateway.openai_router import _get_cloud_embedding_model

        result = _get_cloud_embedding_model("anthropic")
        assert result is None, (
            f"Anthropic has no embeddings API — expected None, got {result!r}"
        )

    @pytest.mark.asyncio
    async def test_get_cloud_embedding_model_openai_returns_default(self):
        """_get_cloud_embedding_model('openai') returns the default model name."""
        from yashigani.gateway.openai_router import _get_cloud_embedding_model

        result = _get_cloud_embedding_model("openai")
        assert result is not None, "OpenAI must have a default embedding model"
        assert "embedding" in result.lower() or "text" in result.lower(), (
            f"Expected a text-embedding model name, got {result!r}"
        )

    def test_get_cloud_embedding_model_env_override(self, monkeypatch):
        """YASHIGANI_OPENAI_EMBEDDING_MODEL env var overrides the default."""
        monkeypatch.setenv("YASHIGANI_OPENAI_EMBEDDING_MODEL", "text-embedding-ada-002")
        from yashigani.gateway.openai_router import _get_cloud_embedding_model

        result = _get_cloud_embedding_model("openai")
        assert result == "text-embedding-ada-002", (
            f"Env override not respected, got {result!r}"
        )


# ---------------------------------------------------------------------------
# EMBED-004 — OPA deny → fail-closed
# ---------------------------------------------------------------------------

class TestOpaDenyFailClosed:
    """EMBED-004: OPA deny → 403, fail-closed."""

    @pytest.mark.asyncio
    async def test_opa_deny_returns_403(self):
        """OPA denies → 403 policy_denied (fail-closed)."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="hello")

        opa_deny = {
            "allow": False,
            "reason": "sensitivity_ceiling_exceeded",
            "model_allowed": True,
            "routing_safe": True,
            "sensitivity_allowed": False,
        }

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_deny),
        ):
            resp = await create_embeddings(body, req)

        assert resp.status_code == 403, (
            f"Expected 403 on OPA deny, got {resp.status_code}"
        )
        data = json.loads(resp.body)
        assert data["error"]["type"] == "policy_denied"
        assert data["error"]["code"] == "sensitivity_ceiling_exceeded"

    @pytest.mark.asyncio
    async def test_opa_unreachable_returns_403(self):
        """OPA unreachable (opa_unreachable) → 403 fail-closed."""
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()
        # Point opa_url to a real address so _opa_v1_check runs (not dev opt-in)
        _m._state.opa_url = "https://policy:8181"

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="hello")

        # Patch internal_httpx_client to raise a connect error
        import httpx
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            resp = await create_embeddings(body, req)

        assert resp.status_code == 403, (
            f"Expected 403 on OPA unreachable, got {resp.status_code}"
        )
        data = json.loads(resp.body)
        assert data["error"]["code"] == "opa_unreachable"

    @pytest.mark.asyncio
    async def test_opa_v1_check_called_with_correct_path(self):
        """_opa_v1_check is called with request_path='/v1/embeddings'."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="test")

        opa_allow = {
            "allow": True, "reason": "ok",
            "model_allowed": True, "routing_safe": True, "sensitivity_allowed": True,
        }

        cm, _ = _make_ollama_embed_mock([[0.1]])

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_allow),
        ) as mock_opa:
            with patch("httpx.AsyncClient", return_value=cm):
                await create_embeddings(body, req)

        mock_opa.assert_called_once()
        call_kwargs = mock_opa.call_args.kwargs
        assert call_kwargs.get("request_path") == "/v1/embeddings", (
            f"Expected request_path='/v1/embeddings', got {call_kwargs.get('request_path')!r}"
        )

    @pytest.mark.asyncio
    async def test_opa_deny_writes_audit_event(self):
        """OPA deny writes a GatewayRequestEvent with action=DENIED."""
        from yashigani.audit.schema import GatewayRequestEvent
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()
        mock_writer = MagicMock()
        _m._state.audit_writer = mock_writer

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="hello")

        opa_deny = {
            "allow": False, "reason": "identity_not_active",
            "model_allowed": True, "routing_safe": True, "sensitivity_allowed": True,
        }

        with patch(
            "yashigani.gateway.openai_router._opa_v1_check",
            new=AsyncMock(return_value=opa_deny),
        ):
            await create_embeddings(body, req)

        mock_writer.write.assert_called_once()
        written = mock_writer.write.call_args[0][0]
        assert isinstance(written, GatewayRequestEvent), (
            f"Expected GatewayRequestEvent, got {type(written).__name__}"
        )
        assert written.action == "DENIED"
        assert written.path == "/v1/embeddings"


# ---------------------------------------------------------------------------
# EMBED-005 — Auth missing → 401
# ---------------------------------------------------------------------------

class TestAuthMissing:
    """EMBED-005: no auth → 401 AUTHENTICATION_REQUIRED, same as chat."""

    @pytest.mark.asyncio
    async def test_no_auth_header_returns_401(self):
        """Request with no Authorization header → 401."""
        import importlib
        # Reload with a known bearer set
        bearer = "test-internal-bearer-token-for-unit-tests"
        os.environ["YASHIGANI_INTERNAL_BEARER"] = bearer

        import yashigani.gateway.openai_router as _mod
        importlib.reload(_mod)

        _mod._state.identity_registry = None  # no registry

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(_mod.router)
        _mod.configure(opa_url="")

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/v1/embeddings",
            json={"model": "nomic-embed-text", "input": "hello"},
        )
        assert response.status_code == 401, (
            f"Expected 401, got {response.status_code}"
        )
        body = response.json()
        assert body["detail"]["error"] == "AUTHENTICATION_REQUIRED"

    @pytest.mark.asyncio
    async def test_wrong_bearer_returns_401(self):
        """Wrong Bearer token (not the internal bearer) → 401 when no registry."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings
        from starlette.requests import Request

        _reset_router_state()
        # No identity_registry → can't look up API keys → None → 401

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/embeddings",
            "query_string": b"",
            "headers": [
                (b"authorization", b"Bearer wrong-key-xyz"),
            ],
        }
        req = Request(scope)
        body = EmbeddingRequest(model="nomic-embed-text", input="hello")

        with pytest.raises(Exception) as exc_info:
            await create_embeddings(body, req)

        # FastAPI raises HTTPException(401) — verify status code
        from fastapi import HTTPException
        assert isinstance(exc_info.value, HTTPException)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# EMBED-006 — Response shape invariants
# ---------------------------------------------------------------------------

class TestResponseShapeInvariants:
    """Additional shape/contract assertions beyond EMBED-001."""

    @pytest.mark.asyncio
    async def test_model_in_response_matches_actual(self):
        """Response model field reflects what Ollama actually used."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()
        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text:latest", input="test")

        # Ollama may normalise the model name
        cm, _ = _make_ollama_embed_mock([[0.1, 0.2]], model="nomic-embed-text:latest")

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                resp = await create_embeddings(body, req)

        data = json.loads(resp.body)
        assert data["model"] == "nomic-embed-text:latest"

    @pytest.mark.asyncio
    async def test_usage_fields_present(self):
        """usage.prompt_tokens and usage.total_tokens are present (>= 0)."""
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()
        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="usage test")

        cm, _ = _make_ollama_embed_mock([[0.1]])

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                resp = await create_embeddings(body, req)

        data = json.loads(resp.body)
        usage = data.get("usage", {})
        assert "prompt_tokens" in usage, "usage.prompt_tokens must be present"
        assert "total_tokens" in usage, "usage.total_tokens must be present"
        assert usage["prompt_tokens"] >= 0
        assert usage["total_tokens"] >= 0

    @pytest.mark.asyncio
    async def test_audit_forwarded_event_on_success(self):
        """Successful Ollama call writes GatewayRequestEvent with action=FORWARDED."""
        from yashigani.audit.schema import GatewayRequestEvent
        from yashigani.gateway import openai_router as _m
        from yashigani.gateway.openai_router import EmbeddingRequest, create_embeddings

        _reset_router_state()
        mock_writer = MagicMock()
        _m._state.audit_writer = mock_writer

        req = _make_internal_bearer_request()
        body = EmbeddingRequest(model="nomic-embed-text", input="audit test")

        cm, _ = _make_ollama_embed_mock([[0.5]])

        with _make_opa_allow_mock(allow=True):
            with patch("httpx.AsyncClient", return_value=cm):
                await create_embeddings(body, req)

        mock_writer.write.assert_called_once()
        written = mock_writer.write.call_args[0][0]
        assert isinstance(written, GatewayRequestEvent)
        assert written.action == "FORWARDED"
        assert written.path == "/v1/embeddings"
        assert written.method == "POST"
