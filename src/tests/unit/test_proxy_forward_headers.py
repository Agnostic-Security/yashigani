"""Regression: the generic-proxy forward leg must not pass the inbound
Content-Length (or Host) header through to the upstream.

The body may be re-encoded (sanitised) between ingress and forward, and httpx
recomputes Content-Length from ``content=body``. Forwarding the stale inbound
length made h11 raise "Too little data for declared Content-Length" against the
upstream — every forward to a real MCP/upstream server 500'd. (The bug was
latent because the generic forward only completes when an upstream answers.)
"""
import asyncio

import httpx
from starlette.requests import Request

from yashigani.gateway.proxy import _forward


def _make_request(headers: dict) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "server": ("gateway", 8080),
        "path": "/mcp/demo-agent",
        "raw_path": b"/mcp/demo-agent",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("10.0.0.9", 4321),
    }
    return Request(scope)


def test_forward_strips_content_length_and_host():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)

    async def run():
        async with httpx.AsyncClient(base_url="http://mcp-demo:8000", transport=transport) as client:
            req = _make_request({
                "content-length": "999",   # stale / wrong on purpose
                "host": "gateway",
                "content-type": "application/json",
                "x-keep": "yes",
            })
            return await _forward(client, req, "mcp/demo-agent", b"hi", "rid-1")

    resp = asyncio.run(run())
    assert resp.status_code == 200

    h = captured["headers"]
    # Content-Length must reflect the actual forwarded body (2 bytes), never 999.
    assert h.get("content-length") == "2"
    # Host must be the upstream's, not the inbound gateway host.
    assert h.get("host") == "mcp-demo:8000"
    # Non-stripped headers survive.
    assert h.get("x-keep") == "yes"
    assert h.get("x-yashigani-request-id") == "rid-1"
