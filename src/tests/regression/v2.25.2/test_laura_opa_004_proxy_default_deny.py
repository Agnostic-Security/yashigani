"""
LAURA-OPA-004 (2.25.2) regression — proxy response-leg consumer fail-open.

proxy.py `_opa_proxy_response_check` previously did
`bool(result.get("allow", True))` — defaulting to ALLOW when OPA returned an
HTTP-200 body of {"result": {}} (undefined rule: partial bundle load, Helm
bundle where v1_routing.rego failed to load, or proxy_response_decision
undefined for the input shape). This re-fails on the original bug: with the
fix, the absent "allow" key must resolve to DENY.

Mirrors the LAURA-V243-001 fix in openai_router (True -> False).
ASVS V4.1.3. Class-identical to the already-accepted LAURA-V243-001 / YSG-RISK-071.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_gateway_config(opa_url: str = "https://opa:8181"):
    from yashigani.gateway.proxy import GatewayConfig
    return GatewayConfig(upstream_base_url="http://mcp:8080", opa_url=opa_url)


def _make_request():
    req = MagicMock()
    req.method = "POST"
    req.headers = {"Authorization": "Bearer test-key", "cookie": ""}
    req.cookies = {}
    req.url = MagicMock()
    req.url.query = ""
    return req


def _opa_http_response(result_body: dict):
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"result": result_body}
    return resp


def _make_mock_opa_client(return_value):
    c = AsyncMock()
    c.__aenter__ = AsyncMock(return_value=c)
    c.__aexit__ = AsyncMock(return_value=False)
    c.post = AsyncMock(return_value=return_value)
    return c


@pytest.mark.asyncio
async def test_undefined_opa_result_denies():
    """OPA HTTP-200 with {"result": {}} (undefined rule) → DENY (fail-closed)."""
    from yashigani.gateway.proxy import _opa_proxy_response_check

    cfg = _make_gateway_config()
    req = _make_request()
    # The bug: absent "allow" key. Pre-fix this resolved to True (allow).
    mock_client = _make_mock_opa_client(_opa_http_response({}))

    with patch("yashigani.gateway.proxy.internal_httpx_client", return_value=mock_client):
        result = await _opa_proxy_response_check(
            cfg=cfg,
            request=req,
            path="/mcp/tool",
            session_id="sess-001",
            agent_id="",
            user_id="alice",
            response_sensitivity="RESTRICTED",
            pii_detected=False,
            request_id="req-001",
            audit_writer=None,
        )

    assert result["allow"] is False, "undefined OPA result must fail-closed (deny)"


@pytest.mark.asyncio
async def test_explicit_allow_still_passes():
    """Healthy bundle: explicit allow:true still delivers (no regression)."""
    from yashigani.gateway.proxy import _opa_proxy_response_check

    cfg = _make_gateway_config()
    req = _make_request()
    mock_client = _make_mock_opa_client(_opa_http_response({"allow": True, "reason": "ok"}))

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


@pytest.mark.asyncio
async def test_explicit_deny_still_denies():
    from yashigani.gateway.proxy import _opa_proxy_response_check

    cfg = _make_gateway_config()
    req = _make_request()
    mock_client = _make_mock_opa_client(
        _opa_http_response({"allow": False, "reason": "response_sensitivity_exceeds_ceiling"})
    )

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
            audit_writer=None,
        )

    assert result["allow"] is False
    assert result["reason"] == "response_sensitivity_exceeds_ceiling"
