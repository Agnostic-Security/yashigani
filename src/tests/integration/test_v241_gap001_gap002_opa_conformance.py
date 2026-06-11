"""
v2.24.1 — GAP-001 + GAP-002: Integration tests for OPA conformance gaps.

No live OPA or upstream — all external calls are mocked.  Tests exercise the
full handler code path using FastAPI TestClient.

GAP-001 scenarios:
  A. Anonymous principal → 401 (pre-existing guard preserved)
  B. Authenticated service account → OPA evaluate → restricted filter applied;
     agent topology NOT enumerable.
  C. Authenticated human admin → full list returned.
  D. OPA down → 503 for any authenticated caller.

GAP-002 scenarios:
  E. Caller's OPA request check passes → OPA response check denies (CONFIDENTIAL
     response to INTERNAL-ceiling caller) → 403 MCP_RESPONSE_BLOCKED_BY_OPA.
  F. Caller's OPA request check passes → OPA response check passes → 200 with body.
  G. OPA down on response leg → 503 (fail-closed).

Negative regression (compromised internal-bearer cannot enumerate topology):
  H. Internal-bearer service account → models endpoint returns restricted list
     with no agent slugs or service-identity slugs.

All tests run on macOS AND Linux (no platform-specific dependencies).
No Docker/Podman/network required.

ASVS V4.1.1 / V4.1.3 / OWASP API9 / Iris GAP-001 / Iris GAP-002 /
YSG-RISK-066 / YSG-RISK-067 / v2.24.1.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INTERNAL_BEARER_TOKEN = "test-internal-bearer-secret-abc123"


def _opa_models_ok(allow: bool = True, filter_: str = "full"):
    result = MagicMock()
    result.status_code = 200
    result.raise_for_status = MagicMock()
    result.json.return_value = {
        "result": {"allow": allow, "filter": filter_, "reason": "ok"}
    }
    return result


def _opa_proxy_ok(allow: bool = True, reason: str = "ok"):
    result = MagicMock()
    result.status_code = 200
    result.raise_for_status = MagicMock()
    result.json.return_value = {"result": {"allow": allow, "reason": reason}}
    return result


# ---------------------------------------------------------------------------
# GAP-001 Integration Tests
# ---------------------------------------------------------------------------

class TestGap001ModelsOpaIntegration:
    """Integration tests for GET /v1/models OPA gate."""

    @pytest.fixture(autouse=True)
    def patch_internal_bearer(self, monkeypatch):
        """Patch the internal bearer to a known test value."""
        monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", INTERNAL_BEARER_TOKEN)

    @pytest.mark.asyncio
    async def test_A_anonymous_returns_401(self, monkeypatch):
        """Scenario A: Anonymous principal → 401."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: None)

        req = MagicMock()
        req.headers = {}
        with pytest.raises(HTTPException) as exc_info:
            await _mod.list_models(req)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_B_service_account_restricted_no_topology(self, monkeypatch):
        """Scenario B: Service account gets restricted filter; no agent/identity topology."""
        from yashigani.gateway import openai_router as _mod

        svc_identity = {
            "identity_id": "langflow-svc",
            "status": "active",
            "kind": "service",
            "sensitivity_ceiling": "RESTRICTED",
            "allowed_models": ["llama3:8b"],
            "groups": [],
        }
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: svc_identity)

        # OPA returns restricted
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_opa_models_ok(True, "restricted"))

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "agent_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "available_models", [
            {"id": "llama3:8b", "provider": "ollama"},
            {"id": "claude-sonnet", "provider": "anthropic"},
        ])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [{"name": "llama3:8b"}, {"name": "mistral:7b"}]}
            return resp
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = _fake_get

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client), \
             patch("httpx.AsyncClient", return_value=mock_http):
            result = await _mod.list_models(MagicMock())

        ids = {m.id for m in result.data}
        # Only allowed_models content visible
        assert "llama3:8b" in ids
        assert "mistral:7b" not in ids  # not in allowed_models
        assert "claude-sonnet" not in ids  # not in allowed_models
        # No topology
        assert not any(m.id.startswith("@") for m in result.data)
        # identity_registry and agent_registry must NOT have been queried
        _mod._state.identity_registry.list_active.assert_not_called()
        _mod._state.agent_registry.list_all.assert_not_called()

    @pytest.mark.asyncio
    async def test_C_human_admin_full_list(self, monkeypatch):
        """Scenario C: Human admin gets full list including agent topology."""
        from yashigani.gateway import openai_router as _mod

        admin_identity = {
            "identity_id": "admin-console",
            "status": "active",
            "kind": "admin",
            "sensitivity_ceiling": "RESTRICTED",
            "allowed_models": [],
            "groups": [],
        }
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: admin_identity)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_opa_models_ok(True, "full"))

        mock_registry = MagicMock()
        mock_registry.list_active.return_value = [{"slug": "svc-identity-1", "name": "SvcOne"}]
        mock_agent_reg = MagicMock()
        mock_agent_reg.list_all.return_value = [{"name": "claw-agent", "status": "active"}]

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", mock_registry)
        monkeypatch.setattr(_mod._state, "agent_registry", mock_agent_reg)
        monkeypatch.setattr(_mod._state, "available_models", [])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [{"name": "llama3:8b"}]}
            return resp
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = _fake_get

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client), \
             patch("httpx.AsyncClient", return_value=mock_http):
            result = await _mod.list_models(MagicMock())

        ids = {m.id for m in result.data}
        assert "llama3:8b" in ids
        assert "@svc-identity-1" in ids
        assert "@claw-agent" in ids

    @pytest.mark.asyncio
    async def test_D_opa_down_returns_503(self, monkeypatch):
        """Scenario D: OPA unreachable → 503 for any authenticated caller."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: {
            "identity_id": "alice", "status": "active", "kind": "human",
            "sensitivity_ceiling": "INTERNAL", "allowed_models": [], "groups": [],
        })
        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        monkeypatch.setattr(_mod._state, "audit_writer", MagicMock())

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=ConnectionError("OPA down"))

        with patch("yashigani.pki.client.internal_httpx_client", return_value=mock_client):
            with pytest.raises(HTTPException) as exc_info:
                await _mod.list_models(MagicMock())

        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_H_compromised_internal_bearer_cannot_enumerate_topology(self, monkeypatch):
        """Scenario H: Compromised internal-bearer → restricted list, topology not visible."""
        from yashigani.gateway import openai_router as _mod

        # internal-bearer resolves to service kind
        internal_identity = {
            "identity_id": "internal",
            "status": "active",
            "kind": "service",
            "sensitivity_ceiling": "RESTRICTED",
            "allowed_models": [],
            "groups": [],
        }
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: internal_identity)
        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_opa_models_ok(True, "restricted"))

        mock_registry = MagicMock()
        mock_registry.list_active.return_value = [{"slug": "secret-agent-svc", "name": "SecretSvc"}]
        mock_agent_reg = MagicMock()
        mock_agent_reg.list_all.return_value = [{"name": "sensitive-agent", "status": "active"}]

        monkeypatch.setattr(_mod._state, "identity_registry", mock_registry)
        monkeypatch.setattr(_mod._state, "agent_registry", mock_agent_reg)
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "available_models", [])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.json.return_value = {}
            return resp
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.get = _fake_get

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client), \
             patch("httpx.AsyncClient", return_value=mock_http):
            result = await _mod.list_models(MagicMock())

        ids = {m.id for m in result.data}
        assert "@secret-agent-svc" not in ids
        assert "@sensitive-agent" not in ids
        # Registries must NOT have been queried
        mock_registry.list_active.assert_not_called()
        mock_agent_reg.list_all.assert_not_called()


# ---------------------------------------------------------------------------
# GAP-002 Integration Tests
# ---------------------------------------------------------------------------

class TestGap002ProxyResponseOpaIntegration:
    """Integration tests for catch-all proxy response-leg OPA gate."""

    @pytest.mark.asyncio
    async def test_E_confidential_response_denied_for_internal_ceiling_caller(self, monkeypatch):
        """Scenario E: CONFIDENTIAL response denied for caller with INTERNAL ceiling."""
        from yashigani.gateway import proxy as _proxy

        monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
        monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "CONFIDENTIAL")

        # OPA response check denies
        mock_opa_client = AsyncMock()
        mock_opa_client.__aenter__ = AsyncMock(return_value=mock_opa_client)
        mock_opa_client.__aexit__ = AsyncMock(return_value=False)
        mock_opa_client.post = AsyncMock(
            return_value=_opa_proxy_ok(False, "response_sensitivity_exceeds_ceiling")
        )

        import httpx
        fake_upstream = httpx.Response(200, content=b'{"secret": "top-secret-data"}')
        monkeypatch.setattr(_proxy, "_forward", AsyncMock(return_value=fake_upstream))
        monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-001", "", "alice"))
        monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

        cfg = _proxy.GatewayConfig(
            upstream_base_url="http://mcp:8080",
            opa_url="https://opa:8181",
        )
        audit_writer = MagicMock()

        import time as _time
        req = MagicMock()
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.get = lambda k, d="": ""
        req.headers.items = lambda: []
        req.cookies = {}
        req.url = MagicMock()
        req.url.query = ""
        req.body = AsyncMock(return_value=b'{"method":"tools/list"}')

        state = {
            "config": cfg,
            "inspection_pipeline": None,
            "response_inspection_pipeline": None,
            "auth_service": None,
            "chs": None,
            "audit_writer": audit_writer,
            "rate_limiter": None,
            "rbac_store": None,
            "agent_registry": None,
            "jwt_inspector": None,
            "endpoint_rate_limiter": None,
            "response_cache": None,
            "classifier_backend": None,
            "inference_logger": None,
            "anomaly_detector": None,
            "ddos_protector": None,
            "pii_detector": None,
            "http_client": AsyncMock(),
        }

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_opa_client):
            response = await _proxy._proxy_request_body(
                request=req,
                path="/mcp/tools/list",
                state=state,
                _tracer=None,
                _root_span=MagicMock(set_attribute=MagicMock()),
                request_id="req-001",
                cfg=cfg,
                audit_writer=audit_writer,
                start=_time.monotonic(),
            )

        assert response.status_code == 403
        import json
        body = json.loads(response.body)
        assert body["error"] == "MCP_RESPONSE_BLOCKED_BY_OPA"

    @pytest.mark.asyncio
    async def test_F_public_response_delivered_to_caller(self, monkeypatch):
        """Scenario F: PUBLIC response → OPA allows → 200 delivered."""
        from yashigani.gateway import proxy as _proxy

        monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
        monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "PUBLIC")

        mock_opa_client = AsyncMock()
        mock_opa_client.__aenter__ = AsyncMock(return_value=mock_opa_client)
        mock_opa_client.__aexit__ = AsyncMock(return_value=False)
        mock_opa_client.post = AsyncMock(return_value=_opa_proxy_ok(True, "ok"))

        import httpx
        fake_upstream = httpx.Response(200, content=b'{"tools": ["browse", "search"]}')
        monkeypatch.setattr(_proxy, "_forward", AsyncMock(return_value=fake_upstream))
        monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-001", "", "alice"))
        monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

        cfg = _proxy.GatewayConfig(
            upstream_base_url="http://mcp:8080",
            opa_url="https://opa:8181",
        )

        import time as _time
        req = MagicMock()
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.get = lambda k, d="": ""
        req.headers.items = lambda: []
        req.cookies = {}
        req.url = MagicMock()
        req.url.query = ""
        req.body = AsyncMock(return_value=b'{"method":"tools/list"}')

        state = {
            "config": cfg,
            "inspection_pipeline": None,
            "response_inspection_pipeline": None,
            "auth_service": None,
            "chs": None,
            "audit_writer": MagicMock(),
            "rate_limiter": None,
            "rbac_store": None,
            "agent_registry": None,
            "jwt_inspector": None,
            "endpoint_rate_limiter": None,
            "response_cache": None,
            "classifier_backend": None,
            "inference_logger": None,
            "anomaly_detector": None,
            "ddos_protector": None,
            "pii_detector": None,
            "http_client": AsyncMock(),
        }

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_opa_client):
            response = await _proxy._proxy_request_body(
                request=req,
                path="/mcp/tools/list",
                state=state,
                _tracer=None,
                _root_span=MagicMock(set_attribute=MagicMock()),
                request_id="req-001",
                cfg=cfg,
                audit_writer=state["audit_writer"],
                start=_time.monotonic(),
            )

        assert response.status_code == 200
        assert b"browse" in response.body

    @pytest.mark.asyncio
    async def test_G_opa_down_response_leg_returns_503(self, monkeypatch):
        """Scenario G: OPA down on response leg → 503 fail-closed."""
        from yashigani.gateway import proxy as _proxy

        monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
        monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "PUBLIC")

        # OPA unreachable
        mock_opa_client = AsyncMock()
        mock_opa_client.__aenter__ = AsyncMock(return_value=mock_opa_client)
        mock_opa_client.__aexit__ = AsyncMock(return_value=False)
        mock_opa_client.post = AsyncMock(side_effect=ConnectionError("OPA down"))

        import httpx
        fake_upstream = httpx.Response(200, content=b'{"tools": []}')
        monkeypatch.setattr(_proxy, "_forward", AsyncMock(return_value=fake_upstream))
        monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-001", "", "alice"))
        monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

        cfg = _proxy.GatewayConfig(
            upstream_base_url="http://mcp:8080",
            opa_url="https://opa:8181",
        )

        import time as _time
        req = MagicMock()
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.get = lambda k, d="": ""
        req.headers.items = lambda: []
        req.cookies = {}
        req.url = MagicMock()
        req.url.query = ""
        req.body = AsyncMock(return_value=b'{"method":"tools/list"}')

        state = {
            "config": cfg,
            "inspection_pipeline": None,
            "response_inspection_pipeline": None,
            "auth_service": None,
            "chs": None,
            "audit_writer": MagicMock(),
            "rate_limiter": None,
            "rbac_store": None,
            "agent_registry": None,
            "jwt_inspector": None,
            "endpoint_rate_limiter": None,
            "response_cache": None,
            "classifier_backend": None,
            "inference_logger": None,
            "anomaly_detector": None,
            "ddos_protector": None,
            "pii_detector": None,
            "http_client": AsyncMock(),
        }

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_opa_client):
            response = await _proxy._proxy_request_body(
                request=req,
                path="/mcp/tools/list",
                state=state,
                _tracer=None,
                _root_span=MagicMock(set_attribute=MagicMock()),
                request_id="req-001",
                cfg=cfg,
                audit_writer=state["audit_writer"],
                start=_time.monotonic(),
            )

        assert response.status_code == 503
