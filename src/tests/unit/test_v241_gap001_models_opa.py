"""
v2.24.1 — GAP-001: Unit tests for GET /v1/models OPA evaluation.

Covers:
  1. _opa_models_check — human identity → full filter
  2. _opa_models_check — service identity → restricted filter
  3. _opa_models_check — OPA deny → {"allow": False}
  4. _opa_models_check — OPA unreachable (exception) → fail-closed deny
  5. _opa_models_check — OPA not configured + dev opt-in → allow full (dev)
  6. _opa_models_check — OPA not configured + no opt-in → fail-closed deny
  7. list_models — anonymous → 401 (pre-existing behaviour preserved)
  8. list_models — OPA deny → 403
  9. list_models — OPA unreachable → 503
 10. list_models — human identity, full filter → full model list returned
 11. list_models — service identity, restricted filter, allowed_models → filtered list
 12. list_models — service identity, restricted filter, empty allowed_models → Ollama+static excluded
 13. list_models — audit event written on allow (count only, no names)
 14. list_models — audit event written on deny
 15. list_models — human admin gets service-identity and agent topology

ASVS V4.1.1 / OWASP API9 / Iris GAP-001 / YSG-RISK-066 / v2.24.1.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_human_identity(allowed_models=None):
    return {
        "identity_id": "alice",
        "status": "active",
        "kind": "human",
        "sensitivity_ceiling": "INTERNAL",
        "allowed_models": allowed_models or [],
        "groups": [],
    }


def _make_service_identity(allowed_models=None):
    return {
        "identity_id": "langflow-svc",
        "status": "active",
        "kind": "service",
        "sensitivity_ceiling": "RESTRICTED",
        "allowed_models": allowed_models or [],
        "groups": [],
    }


def _make_admin_identity():
    return {
        "identity_id": "admin-console",
        "status": "active",
        "kind": "admin",
        "sensitivity_ceiling": "RESTRICTED",
        "allowed_models": [],
        "groups": [],
    }


def _opa_success(allow: bool, filter_: str = "full", reason: str = "ok"):
    """Mock OPA HTTP response returning the given allow/filter."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"result": {"allow": allow, "filter": filter_, "reason": reason}}
    return mock_resp


# ---------------------------------------------------------------------------
# Tests — _opa_models_check helper
# ---------------------------------------------------------------------------

class TestOpaModelsCheck:
    """Unit tests for the _opa_models_check coroutine."""

    @pytest.mark.asyncio
    async def test_human_identity_full_filter(self, monkeypatch):
        """Human identity with active status gets full filter from OPA."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_opa_success(True, "full", "ok"))

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            result = await _mod._opa_models_check(_make_human_identity())

        assert result["allow"] is True
        assert result["filter"] == "full"
        assert result["reason"] == "ok"

    @pytest.mark.asyncio
    async def test_service_identity_restricted_filter(self, monkeypatch):
        """Service identity gets restricted filter from OPA."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_opa_success(True, "restricted", "ok"))

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            result = await _mod._opa_models_check(_make_service_identity())

        assert result["allow"] is True
        assert result["filter"] == "restricted"

    @pytest.mark.asyncio
    async def test_opa_deny_returns_false(self, monkeypatch):
        """OPA deny → allow=False, filter=denied."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            return_value=_opa_success(False, "denied", "identity_not_active_or_anonymous")
        )

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            result = await _mod._opa_models_check(_make_human_identity())

        assert result["allow"] is False
        assert result["filter"] == "denied"

    @pytest.mark.asyncio
    async def test_opa_unreachable_fail_closed(self, monkeypatch):
        """OPA unreachable (exception) → fail-closed deny."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=ConnectionError("OPA down"))

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            result = await _mod._opa_models_check(_make_human_identity())

        assert result["allow"] is False
        assert result["filter"] == "denied"
        assert "unreachable" in result["reason"] or result["reason"] == "opa_unreachable"

    @pytest.mark.asyncio
    async def test_dev_opt_in_no_opa_url(self, monkeypatch):
        """Dev opt-in (YASHIGANI_OPA_OPTIONAL=true, non-prod) → allow full without OPA."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "true")
        monkeypatch.setenv("YASHIGANI_ENV", "development")

        result = await _mod._opa_models_check(_make_human_identity())

        assert result["allow"] is True
        assert result["filter"] == "full"
        assert "dev_opt_in" in result["reason"]

    @pytest.mark.asyncio
    async def test_no_opa_no_opt_in_fail_closed(self, monkeypatch):
        """No OPA URL, no opt-in → fail-closed deny."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "false")
        monkeypatch.setenv("YASHIGANI_ENV", "development")

        result = await _mod._opa_models_check(_make_human_identity())

        assert result["allow"] is False
        assert result["filter"] == "denied"
        assert "not_configured" in result["reason"]


# ---------------------------------------------------------------------------
# Tests — list_models endpoint
# ---------------------------------------------------------------------------

class TestListModelsOPA:
    """Integration-style unit tests for the list_models FastAPI handler."""

    def _make_request(self, headers=None):
        req = MagicMock()
        req.headers = headers or {"Authorization": "Bearer test-key"}
        req.cookies = {}
        return req

    @pytest.mark.asyncio
    async def test_anonymous_returns_401(self, monkeypatch):
        """Unauthenticated caller → 401 (pre-existing behaviour)."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: None)

        req = self._make_request()
        with pytest.raises(HTTPException) as exc_info:
            await _mod.list_models(req)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_opa_deny_returns_403(self, monkeypatch):
        """OPA deny → 403."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: _make_human_identity())
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": False, "filter": "denied", "reason": "identity_not_active_or_anonymous"}
        ))
        monkeypatch.setattr(_mod._state, "audit_writer", MagicMock())

        req = self._make_request()
        with pytest.raises(HTTPException) as exc_info:
            await _mod.list_models(req)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_opa_unreachable_returns_503(self, monkeypatch):
        """OPA unreachable → 503."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: _make_human_identity())
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": False, "filter": "denied", "reason": "opa_unreachable"}
        ))
        monkeypatch.setattr(_mod._state, "audit_writer", MagicMock())

        req = self._make_request()
        with pytest.raises(HTTPException) as exc_info:
            await _mod.list_models(req)
        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_human_gets_full_list(self, monkeypatch):
        """Human with full filter → agents and service identities are included."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: _make_human_identity())
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "full", "reason": "ok"}
        ))
        # Disable Ollama, identity registry, and agent registry
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", None)
        monkeypatch.setattr(_mod._state, "agent_registry", None)
        monkeypatch.setattr(_mod._state, "available_models", [
            {"id": "llama3:8b", "provider": "ollama"},
            {"id": "claude-sonnet", "provider": "anthropic"},
        ])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        # Patch Ollama HTTP call to return 2 models
        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [
                {"name": "llama3:8b"},
                {"name": "mistral:7b"},
            ]}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        import httpx as _httpx
        with patch("httpx.AsyncClient", return_value=mock_client):
            req = self._make_request()
            result = await _mod.list_models(req)

        ids = {m.id for m in result.data}
        # Ollama models from API + static available_models
        assert "llama3:8b" in ids
        assert "mistral:7b" in ids
        assert "claude-sonnet" in ids

    @pytest.mark.asyncio
    async def test_service_restricted_filter_allowed_models(self, monkeypatch):
        """Service account with restricted filter gets only allowed_models."""
        from yashigani.gateway import openai_router as _mod

        svc_identity = _make_service_identity(allowed_models=["llama3:8b"])
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: svc_identity)
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "restricted", "reason": "ok"}
        ))
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", MagicMock())  # should NOT be queried
        monkeypatch.setattr(_mod._state, "agent_registry", MagicMock())     # should NOT be queried
        monkeypatch.setattr(_mod._state, "available_models", [
            {"id": "llama3:8b", "provider": "ollama"},
            {"id": "claude-sonnet", "provider": "anthropic"},  # NOT in allowed_models
        ])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [
                {"name": "llama3:8b"},
                {"name": "mistral:7b"},  # NOT in allowed_models
            ]}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        with patch("httpx.AsyncClient", return_value=mock_client):
            req = self._make_request()
            result = await _mod.list_models(req)

        ids = {m.id for m in result.data}
        assert "llama3:8b" in ids
        assert "mistral:7b" not in ids      # not in allowed_models
        assert "claude-sonnet" not in ids   # not in allowed_models
        # Service topology should NOT be in restricted list
        assert not any(i.startswith("@") for i in ids)

    @pytest.mark.asyncio
    async def test_service_restricted_empty_allowed_models_excludes_topology(self, monkeypatch):
        """Service account with empty allowed_models → Ollama and static excluded from restricted list."""
        from yashigani.gateway import openai_router as _mod

        svc_identity = _make_service_identity(allowed_models=[])
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: svc_identity)
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "restricted", "reason": "ok"}
        ))
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "agent_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "available_models", [
            {"id": "llama3:8b", "provider": "ollama"},
        ])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [{"name": "llama3:8b"}]}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        with patch("httpx.AsyncClient", return_value=mock_client):
            req = self._make_request()
            result = await _mod.list_models(req)

        # allowed_models is empty set, so no Ollama or static models exposed
        assert len(result.data) == 0

    @pytest.mark.asyncio
    async def test_audit_event_written_on_allow(self, monkeypatch):
        """MODELS_LIST_REQUESTED audit event is written on allow with correct fields."""
        from yashigani.gateway import openai_router as _mod
        from yashigani.audit.schema import ModelsListRequestedEvent

        audit_writer = MagicMock()
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: _make_human_identity())
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "full", "reason": "ok"}
        ))
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", None)
        monkeypatch.setattr(_mod._state, "agent_registry", None)
        monkeypatch.setattr(_mod._state, "available_models", [])
        monkeypatch.setattr(_mod._state, "audit_writer", audit_writer)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [{"name": "llama3:8b"}]}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        with patch("httpx.AsyncClient", return_value=mock_client):
            await _mod.list_models(self._make_request())

        audit_writer.write.assert_called_once()
        event = audit_writer.write.call_args[0][0]
        assert isinstance(event, ModelsListRequestedEvent)
        assert event.action == "allowed"
        assert event.opa_filter == "full"
        assert event.identity_id == "alice"
        assert event.model_count == 1  # 1 Ollama model fetched

    @pytest.mark.asyncio
    async def test_audit_event_written_on_deny(self, monkeypatch):
        """MODELS_LIST_REQUESTED audit event is written on deny."""
        from yashigani.gateway import openai_router as _mod
        from yashigani.audit.schema import ModelsListRequestedEvent
        from fastapi import HTTPException

        audit_writer = MagicMock()
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: _make_human_identity())
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": False, "filter": "denied", "reason": "identity_not_active_or_anonymous"}
        ))
        monkeypatch.setattr(_mod._state, "audit_writer", audit_writer)

        with pytest.raises(HTTPException):
            await _mod.list_models(self._make_request())

        audit_writer.write.assert_called_once()
        event = audit_writer.write.call_args[0][0]
        assert isinstance(event, ModelsListRequestedEvent)
        assert event.action == "denied"
        assert event.model_count == 0

    @pytest.mark.asyncio
    async def test_compromised_internal_bearer_gets_restricted_not_full_topology(self, monkeypatch):
        """Compromised internal-bearer (service kind) cannot enumerate agent topology."""
        from yashigani.gateway import openai_router as _mod

        # Internal bearer resolves to service kind
        svc_identity = {
            "identity_id": "internal",
            "status": "active",
            "kind": "service",
            "sensitivity_ceiling": "RESTRICTED",
            "allowed_models": [],
            "groups": [],
        }
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: svc_identity)
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "restricted", "reason": "ok"}
        ))
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        # Registry and agent_registry are NOT None — they WOULD return topology on full filter
        mock_registry = MagicMock()
        mock_registry.list_active.return_value = [
            {"slug": "openclaw-svc", "name": "OpenClaw"},
        ]
        monkeypatch.setattr(_mod._state, "identity_registry", mock_registry)
        mock_agent_reg = MagicMock()
        mock_agent_reg.list_all.return_value = [
            {"name": "claw-agent", "status": "active"},
        ]
        monkeypatch.setattr(_mod._state, "agent_registry", mock_agent_reg)
        monkeypatch.setattr(_mod._state, "available_models", [])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404  # Ollama down
            resp.json.return_value = {}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _mod.list_models(self._make_request())

        ids = {m.id for m in result.data}
        # Topology must NOT be enumerable for service accounts on restricted filter
        assert "@openclaw-svc" not in ids
        assert "@claw-agent" not in ids
        # identity_registry and agent_registry list methods should NOT have been called
        mock_registry.list_active.assert_not_called()
        mock_agent_reg.list_all.assert_not_called()
