"""
v2.24.1 — GAP-002: Unit tests for catch-all proxy response-leg OPA check.

Covers:
  1. _opa_proxy_response_check — OPA allow → passthrough
  2. _opa_proxy_response_check — OPA deny → {"allow": False, "reason": ...}
  3. _opa_proxy_response_check — OPA unreachable → fail-closed deny
  4. _opa_proxy_response_check — OPA not configured + dev opt-in → allow
  5. _opa_proxy_response_check — OPA not configured + no opt-in → fail-closed deny
  6. _opa_proxy_response_check — audit event McpResponseBlockedByOpaEvent on deny
  7. _opa_proxy_response_check — audit event ProxyOpaResponseCheckFailedEvent on error
  8. _proxy_response_sensitivity — pipeline absent → "PUBLIC"
  9. _proxy_response_sensitivity — pipeline present, classifies CONFIDENTIAL
 10. _proxy_response_sensitivity — pipeline raises → graceful "PUBLIC" fallback
 11. Proxy handler — OPA deny returns 403 (policy) with MCP_RESPONSE_BLOCKED_BY_OPA
 12. Proxy handler — OPA unreachable returns 503
 13. Proxy handler — OPA allow → response delivered normally

ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3 /
Iris GAP-002 / YSG-RISK-067 / v2.24.1.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_gateway_config(opa_url: str = "https://opa:8181"):
    from yashigani.gateway.proxy import GatewayConfig
    return GatewayConfig(
        upstream_base_url="http://mcp:8080",
        opa_url=opa_url,
    )


def _make_request(
    path: str = "/mcp/tool",
    session_id: str = "sess-001",
    agent_id: str = "",
    auth_header: str = "Bearer test-key",
):
    req = MagicMock()
    req.method = "POST"
    req.headers = {"Authorization": auth_header, "cookie": ""}
    req.cookies = {}
    req.url = MagicMock()
    req.url.query = ""
    return req


def _opa_http_response(allow: bool, reason: str = "ok"):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"result": {"allow": allow, "reason": reason}}
    return mock_resp


def _make_mock_opa_client(return_value):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=return_value)
    return mock_client


# ---------------------------------------------------------------------------
# Tests — _opa_proxy_response_check helper
# ---------------------------------------------------------------------------

class TestOpaProxyResponseCheck:
    """Unit tests for the _opa_proxy_response_check coroutine."""

    @pytest.mark.asyncio
    async def test_opa_allow(self, monkeypatch):
        """OPA allow → {"allow": True}."""
        from yashigani.gateway.proxy import _opa_proxy_response_check

        cfg = _make_gateway_config()
        req = _make_request()
        mock_client = _make_mock_opa_client(_opa_http_response(True, "ok"))

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_client):
            result = await _opa_proxy_response_check(
                cfg=cfg,
                request=req,
                path="/mcp/tool",
                session_id="sess-001",
                agent_id="",
                user_id="alice",
                response_sensitivity="PUBLIC",
                pii_detected=False,
                request_id="req-001",
                audit_writer=None,
            )

        assert result["allow"] is True
        assert result["reason"] == "ok"

    @pytest.mark.asyncio
    async def test_opa_deny_ceiling_exceeded(self, monkeypatch):
        """OPA deny (sensitivity exceeds ceiling) → {"allow": False}."""
        from yashigani.gateway.proxy import _opa_proxy_response_check

        cfg = _make_gateway_config()
        req = _make_request()
        mock_client = _make_mock_opa_client(
            _opa_http_response(False, "response_sensitivity_exceeds_ceiling")
        )
        audit_writer = MagicMock()

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_client):
            result = await _opa_proxy_response_check(
                cfg=cfg,
                request=req,
                path="/mcp/tool",
                session_id="sess-001",
                agent_id="",
                user_id="alice",
                response_sensitivity="CONFIDENTIAL",
                pii_detected=False,
                request_id="req-001",
                audit_writer=audit_writer,
            )

        assert result["allow"] is False
        assert result["reason"] == "response_sensitivity_exceeds_ceiling"

    @pytest.mark.asyncio
    async def test_opa_unreachable_fail_closed(self, monkeypatch):
        """OPA unreachable → fail-closed deny."""
        from yashigani.gateway.proxy import _opa_proxy_response_check

        cfg = _make_gateway_config()
        req = _make_request()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=ConnectionError("OPA down"))
        audit_writer = MagicMock()

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_client):
            result = await _opa_proxy_response_check(
                cfg=cfg,
                request=req,
                path="/mcp/tool",
                session_id="sess-001",
                agent_id="",
                user_id="alice",
                response_sensitivity="PUBLIC",
                pii_detected=False,
                request_id="req-001",
                audit_writer=audit_writer,
            )

        assert result["allow"] is False
        assert result["reason"] == "opa_unreachable"

    @pytest.mark.asyncio
    async def test_dev_opt_in_no_opa_url(self, monkeypatch):
        """Dev opt-in (YASHIGANI_OPA_OPTIONAL=true, non-prod) → allow without OPA."""
        from yashigani.gateway.proxy import _opa_proxy_response_check, GatewayConfig

        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="")
        req = _make_request()
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "true")
        monkeypatch.setenv("YASHIGANI_ENV", "development")

        result = await _opa_proxy_response_check(
            cfg=cfg,
            request=req,
            path="/mcp/tool",
            session_id="sess-001",
            agent_id="",
            user_id="alice",
            response_sensitivity="PUBLIC",
            pii_detected=False,
            request_id="req-001",
            audit_writer=None,
        )

        assert result["allow"] is True
        assert "dev_opt_in" in result["reason"]

    @pytest.mark.asyncio
    async def test_no_opa_url_no_opt_in_fail_closed(self, monkeypatch):
        """No OPA URL + no opt-in → fail-closed deny."""
        from yashigani.gateway.proxy import _opa_proxy_response_check, GatewayConfig

        cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="")
        req = _make_request()
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "false")
        monkeypatch.setenv("YASHIGANI_ENV", "development")

        result = await _opa_proxy_response_check(
            cfg=cfg,
            request=req,
            path="/mcp/tool",
            session_id="sess-001",
            agent_id="",
            user_id="alice",
            response_sensitivity="PUBLIC",
            pii_detected=False,
            request_id="req-001",
            audit_writer=None,
        )

        assert result["allow"] is False
        assert "not_configured" in result["reason"]

    @pytest.mark.asyncio
    async def test_audit_event_on_deny(self, monkeypatch):
        """McpResponseBlockedByOpaEvent is written on OPA deny."""
        from yashigani.gateway.proxy import _opa_proxy_response_check
        from yashigani.audit.schema import McpResponseBlockedByOpaEvent

        cfg = _make_gateway_config()
        req = _make_request()
        mock_client = _make_mock_opa_client(
            _opa_http_response(False, "response_sensitivity_exceeds_ceiling")
        )
        audit_writer = MagicMock()

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_client):
            await _opa_proxy_response_check(
                cfg=cfg,
                request=req,
                path="/mcp/tool",
                session_id="sess-001",
                agent_id="",
                user_id="alice",
                response_sensitivity="CONFIDENTIAL",
                pii_detected=False,
                request_id="req-001",
                audit_writer=audit_writer,
            )

        audit_writer.write.assert_called_once()
        event = audit_writer.write.call_args[0][0]
        assert isinstance(event, McpResponseBlockedByOpaEvent)
        assert event.action == "denied"
        assert event.response_sensitivity == "CONFIDENTIAL"
        assert event.deny_reason == "response_sensitivity_exceeds_ceiling"

    @pytest.mark.asyncio
    async def test_audit_event_on_opa_error(self, monkeypatch):
        """ProxyOpaResponseCheckFailedEvent is written on OPA exception."""
        from yashigani.gateway.proxy import _opa_proxy_response_check
        from yashigani.audit.schema import ProxyOpaResponseCheckFailedEvent

        cfg = _make_gateway_config()
        req = _make_request()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=ConnectionError("OPA down"))
        audit_writer = MagicMock()

        with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_client):
            await _opa_proxy_response_check(
                cfg=cfg,
                request=req,
                path="/mcp/tool",
                session_id="sess-001",
                agent_id="",
                user_id="alice",
                response_sensitivity="PUBLIC",
                pii_detected=False,
                request_id="req-001",
                audit_writer=audit_writer,
            )

        audit_writer.write.assert_called_once()
        event = audit_writer.write.call_args[0][0]
        assert isinstance(event, ProxyOpaResponseCheckFailedEvent)
        assert event.outcome == "exception"
        assert event.action == "denied_fail_closed"


# ---------------------------------------------------------------------------
# Tests — _proxy_response_sensitivity helper
# ---------------------------------------------------------------------------

class TestProxyResponseSensitivity:
    """Unit tests for _proxy_response_sensitivity."""

    def test_no_pipeline_returns_public(self):
        """No pipeline → always PUBLIC."""
        from yashigani.gateway.proxy import _proxy_response_sensitivity

        result = _proxy_response_sensitivity(
            resp_pipeline=None,
            content=b'{"result": "some confidential data"}',
            session_id="sess-001",
            agent_id="",
            request_id="req-001",
        )
        assert result == "PUBLIC"

    def test_empty_content_returns_public(self):
        """Empty content → PUBLIC regardless of pipeline."""
        from yashigani.gateway.proxy import _proxy_response_sensitivity

        mock_pipeline = MagicMock()
        result = _proxy_response_sensitivity(
            resp_pipeline=mock_pipeline,
            content=b"",
            session_id="sess-001",
            agent_id="",
            request_id="req-001",
        )
        assert result == "PUBLIC"
        mock_pipeline.inspect.assert_not_called()

    def test_pipeline_classifies_confidential(self):
        """Pipeline returns CONFIDENTIAL → function returns CONFIDENTIAL."""
        from yashigani.gateway.proxy import _proxy_response_sensitivity

        mock_result = MagicMock()
        mock_result.response_sensitivity = "CONFIDENTIAL"
        mock_pipeline = MagicMock()
        mock_pipeline.inspect.return_value = mock_result

        result = _proxy_response_sensitivity(
            resp_pipeline=mock_pipeline,
            content=b'{"secret": "top-secret-data"}',
            session_id="sess-001",
            agent_id="",
            request_id="req-001",
        )
        assert result == "CONFIDENTIAL"

    def test_pipeline_raises_returns_public_fallback(self):
        """Pipeline exception → graceful PUBLIC fallback."""
        from yashigani.gateway.proxy import _proxy_response_sensitivity

        mock_pipeline = MagicMock()
        mock_pipeline.inspect.side_effect = RuntimeError("classifier unavailable")

        result = _proxy_response_sensitivity(
            resp_pipeline=mock_pipeline,
            content=b'{"data": "something"}',
            session_id="sess-001",
            agent_id="",
            request_id="req-001",
        )
        assert result == "PUBLIC"

    def test_pipeline_returns_unknown_sensitivity_falls_back_to_public(self):
        """Unknown sensitivity label from pipeline → PUBLIC (safe fallback)."""
        from yashigani.gateway.proxy import _proxy_response_sensitivity

        mock_result = MagicMock()
        mock_result.response_sensitivity = "ULTRA_SECRET"  # not in canonical set
        mock_pipeline = MagicMock()
        mock_pipeline.inspect.return_value = mock_result

        result = _proxy_response_sensitivity(
            resp_pipeline=mock_pipeline,
            content=b'{"data": "something"}',
            session_id="sess-001",
            agent_id="",
            request_id="req-001",
        )
        assert result == "PUBLIC"

    def test_pipeline_result_missing_attribute_returns_public(self):
        """Pipeline result without response_sensitivity attr → PUBLIC."""
        from yashigani.gateway.proxy import _proxy_response_sensitivity

        mock_result = MagicMock(spec=[])  # no attributes
        mock_pipeline = MagicMock()
        mock_pipeline.inspect.return_value = mock_result

        result = _proxy_response_sensitivity(
            resp_pipeline=mock_pipeline,
            content=b'{"data": "something"}',
            session_id="sess-001",
            agent_id="",
            request_id="req-001",
        )
        assert result == "PUBLIC"


# ---------------------------------------------------------------------------
# Tests — Integration: proxy handler end-to-end with OPA response leg
# ---------------------------------------------------------------------------

class TestProxyHandlerResponseOPA:
    """End-to-end handler tests validating the OPA response-leg block/allow."""

    def _make_state(self, opa_allow: bool = True, opa_reason: str = "ok"):
        """Minimal state dict for _proxy_request_body (minus routing/ratelimit)."""
        return {
            "config": _make_gateway_config(),
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

    @pytest.mark.asyncio
    async def test_opa_deny_returns_403(self, monkeypatch):
        """OPA deny on response leg → handler returns 403."""
        from yashigani.gateway import proxy as _proxy

        # Patch _opa_check (request leg) to allow
        monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
        # Patch _opa_proxy_response_check (response leg) to deny
        monkeypatch.setattr(_proxy, "_opa_proxy_response_check", AsyncMock(
            return_value={"allow": False, "reason": "response_sensitivity_exceeds_ceiling"}
        ))
        # Patch _proxy_response_sensitivity
        monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "CONFIDENTIAL")

        # Build a minimal fake upstream response
        import httpx
        fake_upstream = httpx.Response(200, content=b'{"result": "secret data"}')

        # Patch _forward to return fake_upstream
        monkeypatch.setattr(_proxy, "_forward", AsyncMock(return_value=fake_upstream))

        state = self._make_state()
        cfg = state["config"]
        req = MagicMock()
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.get = lambda k, d="": "" if "authorization" in k.lower() else d
        req.headers.items = lambda: [("content-type", "application/json")]
        req.cookies = {}
        req.url = MagicMock()
        req.url.query = ""
        req.body = AsyncMock(return_value=b'{"method":"tools/list"}')

        # Patch _extract_identity, _get_client_ip
        monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-001", "", "alice"))
        monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

        import time as _time
        tracer = None
        root_span = MagicMock()
        root_span.set_attribute = MagicMock()

        response = await _proxy._proxy_request_body(
            request=req,
            path="/mcp/tools/list",
            state=state,
            _tracer=tracer,
            _root_span=root_span,
            request_id="req-001",
            cfg=cfg,
            audit_writer=state["audit_writer"],
            start=_time.monotonic(),
        )

        assert response.status_code == 403
        import json
        body = json.loads(response.body)
        assert body["error"] == "MCP_RESPONSE_BLOCKED_BY_OPA"

    @pytest.mark.asyncio
    async def test_opa_unreachable_returns_503(self, monkeypatch):
        """OPA unreachable on response leg → handler returns 503."""
        from yashigani.gateway import proxy as _proxy

        monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
        monkeypatch.setattr(_proxy, "_opa_proxy_response_check", AsyncMock(
            return_value={"allow": False, "reason": "opa_unreachable"}
        ))
        monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "PUBLIC")

        import httpx
        fake_upstream = httpx.Response(200, content=b'{"result": "data"}')
        monkeypatch.setattr(_proxy, "_forward", AsyncMock(return_value=fake_upstream))

        state = self._make_state()
        cfg = state["config"]
        req = MagicMock()
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.get = lambda k, d="": ""
        req.headers.items = lambda: []
        req.cookies = {}
        req.url = MagicMock()
        req.url.query = ""
        req.body = AsyncMock(return_value=b'{"method":"tools/list"}')

        monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-001", "", "alice"))
        monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

        import time as _time
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

    @pytest.mark.asyncio
    async def test_opa_allow_delivers_response(self, monkeypatch):
        """OPA allow on response leg → handler delivers the upstream response."""
        from yashigani.gateway import proxy as _proxy

        monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
        monkeypatch.setattr(_proxy, "_opa_proxy_response_check", AsyncMock(
            return_value={"allow": True, "reason": "ok"}
        ))
        monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "PUBLIC")

        import httpx
        fake_upstream = httpx.Response(200, content=b'{"result": "clean data"}')
        monkeypatch.setattr(_proxy, "_forward", AsyncMock(return_value=fake_upstream))

        state = self._make_state()
        cfg = state["config"]
        req = MagicMock()
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.get = lambda k, d="": ""
        req.headers.items = lambda: []
        req.cookies = {}
        req.url = MagicMock()
        req.url.query = ""
        req.body = AsyncMock(return_value=b'{"method":"tools/list"}')

        monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-001", "", "alice"))
        monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

        import time as _time
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
        assert b"clean data" in response.body
