"""
Regression tests — YSG-RISK-167 (chat-path repair, 2026-07-30).

Root cause: backoffice/routes/user_ui.py::user_chat_proxy — the SOLE browser
chat path — always returned StreamingResponse(..., media_type="text/event-
stream") regardless of the gateway's real HTTP status, which Starlette
defaults to 200. Every agent-dispatch failure (502/404/405/500/503) and every
PII/OPA block (403) therefore reached the browser as HTTP 200, and sse.js's
`resp.ok` branch (which correctly distinguishes 403 from other errors) never
even ran — the browser saw a "successful" empty/garbled stream and the user
saw nothing.

Live-confirmed via probes against the docker-leg stack (`docker/secrets`
throwaway user, `/user/chat/completions`):
  @letta          -> gateway 502 agent_unreachable   -> proxy: status=200 (BUG)
  @openclaw       -> gateway 500 agent_upstream_error -> proxy: status=200 (BUG)
  @agent_langflow -> gateway 404 agent_not_found      -> proxy: status=200 (BUG)
  PII block       -> gateway 403 pii_detected         -> proxy: status=200 (BUG)

Fix: user_chat_proxy opens the upstream request and inspects the REAL status
BEFORE deciding how to respond. Only 200/201/206 becomes a StreamingResponse;
everything else becomes a JSONResponse carrying the gateway's own status code
+ body, so the browser (and sse.js's existing pre-stream contract) sees the
real status.

The frontend half (sse.js recognising a genuine mid-stream `data:
{"error":{...}}` frame — the residual case where headers are ALREADY
committed as 200 before a failure occurs, e.g. an upstream ConnectError after
generation has started) has no Python harness in this repo (no JS test
runner) — it is exercised live by Ava's
`src/tests/playwright/test_chat_live_e2e.py`, per the chat-path-repair brief.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    _FASTAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FASTAPI_AVAILABLE = False


def _make_app():
    """Mount the REAL user_ui router with UserSession + identity_registry
    dependencies satisfied, so the actual user_chat_proxy code runs."""
    import yashigani.backoffice.routes.user_ui as ui_mod
    from yashigani.backoffice.middleware import require_user_session

    app = FastAPI()
    app.include_router(ui_mod.router)

    fake_session = MagicMock()
    fake_session.account_id = "550e8400-e29b-41d4-a716-446655440000"
    app.dependency_overrides[require_user_session] = lambda: fake_session

    mock_registry = MagicMock()
    mock_registry.get_by_account_id.return_value = {
        "identity_id": "idnt_test0001",
        "status": "active",
    }
    ui_mod.backoffice_state.identity_registry = mock_registry
    return app, ui_mod


class _FakeUpstreamResponse:
    """Mimics the subset of httpx.Response used by user_chat_proxy's
    stream=True send() path."""

    def __init__(self, status_code: int, body: bytes):
        self.status_code = status_code
        self._body = body

    async def aread(self) -> bytes:
        return self._body

    async def aclose(self) -> None:
        return None

    async def aiter_bytes(self):
        yield self._body


def _patch_httpx_client(monkeypatch, upstream_status: int, upstream_body: dict):
    """Patch httpx.AsyncClient so client.send(...) returns a fake response
    with the given status/body, mirroring what the real gateway would send."""
    fake_resp = _FakeUpstreamResponse(
        upstream_status, json.dumps(upstream_body).encode("utf-8")
    )

    mock_client = MagicMock()
    mock_client.build_request = MagicMock(return_value=MagicMock())
    mock_client.send = AsyncMock(return_value=fake_resp)
    mock_client.aclose = AsyncMock(return_value=None)

    monkeypatch.setattr(
        "yashigani.backoffice.routes.user_ui.httpx.AsyncClient",
        MagicMock(return_value=mock_client),
    )
    return mock_client


@pytest.mark.skipif(not _FASTAPI_AVAILABLE, reason="fastapi not available")
class TestRisk167RealStatusPreserved:
    """user_chat_proxy must forward the gateway's REAL status code, never a
    fake 200, for every non-2xx upstream response."""

    def _post(self, monkeypatch, upstream_status: int, upstream_body: dict):
        monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "test-bearer-value")
        app, _ui_mod = _make_app()
        _patch_httpx_client(monkeypatch, upstream_status, upstream_body)
        client = TestClient(app, raise_server_exceptions=False)
        return client.post(
            "/user/chat/completions",
            json={"model": "@letta", "messages": [{"role": "user", "content": "hi"}]},
        )

    def test_agent_unreachable_502_preserved(self, monkeypatch):
        """@letta agent_unreachable (502) must reach the browser as 502, not 200."""
        resp = self._post(
            monkeypatch, 502,
            {"error": {"message": "Agent @letta (Letta) unreachable",
                       "type": "agent_error", "code": "agent_unreachable"}},
        )
        assert resp.status_code == 502, (
            f"YSG-RISK-167 regression: expected 502, got {resp.status_code} "
            f"body={resp.text!r}"
        )
        assert resp.json()["error"]["code"] == "agent_unreachable"

    def test_agent_upstream_500_preserved(self, monkeypatch):
        """@openclaw agent_upstream_error (500) must reach the browser as 500."""
        resp = self._post(
            monkeypatch, 500,
            {"error": {"message": "Agent @openclaw returned HTTP 500",
                       "type": "agent_error", "code": "agent_upstream_error"}},
        )
        assert resp.status_code == 500
        assert resp.json()["error"]["code"] == "agent_upstream_error"

    def test_agent_not_found_404_preserved(self, monkeypatch):
        """@agent_langflow agent_not_found (404) must reach the browser as 404."""
        resp = self._post(
            monkeypatch, 404,
            {"error": {"message": "Agent @agent_langflow not found or not active",
                       "type": "agent_error", "code": "agent_not_found"}},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "agent_not_found"

    def test_pii_block_403_preserved(self, monkeypatch):
        """A PII/OPA-block (403) must reach the browser as 403 (sse.js's
        existing onBlocked contract depends on the REAL 403 status)."""
        resp = self._post(
            monkeypatch, 403,
            {"error": {"message": "Blocked by policy.",
                       "type": "pii_blocked", "code": "pii_detected"}},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "pii_detected"

    def test_genuine_2xx_still_streams(self, monkeypatch):
        """A genuine 200 upstream must still become an SSE StreamingResponse
        (no regression on the happy path)."""
        monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "test-bearer-value")
        app, _ui_mod = _make_app()

        fake_resp = _FakeUpstreamResponse(200, b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')
        mock_client = MagicMock()
        mock_client.build_request = MagicMock(return_value=MagicMock())
        mock_client.send = AsyncMock(return_value=fake_resp)
        mock_client.aclose = AsyncMock(return_value=None)
        monkeypatch.setattr(
            "yashigani.backoffice.routes.user_ui.httpx.AsyncClient",
            MagicMock(return_value=mock_client),
        )

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/user/chat/completions",
            json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
