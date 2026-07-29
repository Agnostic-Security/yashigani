# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-025 (chat silent hang) and V50-026 (injection block invisible).

Both are the same class of bug: the gateway/backend side is CORRECT (a real
model exists and is shown in the composer; the mechanical injection detector
correctly 403s), but the browser never surfaces the right thing to the user —
V50-025 sends the wrong `model` and the request 422s with no visible error;
V50-026's proxy silently downgrades a 403 into an empty, unlabelled 200 SSE
frame that decode.js/ys-verdict-banner can't render anything from.

V50-025 root cause (chat-view.js):
    `_currentModel()` returned `selectedModel || activeAgentId || 'default'`.
    `selectedModel` starts '' and only becomes non-empty once the user
    manually changes the MODEL <select> (`_onModelChange`). But the <select>
    itself renders with options from `models` (GET /user/models) as soon as
    that request resolves — and because no <option> matched the empty/
    agent-id `sel` computed by `_modelOptions()`, the BROWSER defaulted to
    showing its first entry (e.g. qwen2.5:3b) while `selectedModel` stayed
    ''. The first Send therefore targeted `activeAgentId` (a bundled agent
    id like `agnt_langflow`, not a model) -> gateway 422 `unknown model` ->
    the chat bubble streamed nothing and the UI hung with no error.

    Fix: `updated()` now calls `_syncDefaultModelSelection()` the first time
    `models` populates with no selection yet, which reads the just-rendered
    <select>'s live value (falling back to `models[0]`) into
    `this.selectedModel` and echoes it to the app via `ys-model-select` —
    exactly the pattern `_onModelChange` already uses for a manual pick.

V50-026 root cause (backoffice/routes/user_ui.py `user_chat_proxy`):
    The proxy ALWAYS returned `StreamingResponse(..., media_type=
    "text/event-stream")`, whose default HTTP status is 200 REGARDLESS of the
    gateway's real status. When the gateway 403'd a mechanically-blocked
    injection (`request_injection_blocked`), the proxy's generator read the
    error body and re-yielded it as a single SSE `data: {...}` frame —  a
    `{"error": {...}}` shape that matches neither the structured
    decision_codes/user_alert/blocked contract (decode.js) nor `!resp.ok`
    (sse.js's pre-stream onBlocked path). The browser saw HTTP 200 with one
    unrecognised SSE frame, `onMessageDone('', null)` fired, and the
    assistant bubble finished EMPTY — no verdict banner, no error, no
    loading-state explanation.

    Fix: open the gateway connection with `client.send(request, stream=True)`
    so the status line is available before any body is consumed. Non-2xx now
    returns a real `Response` carrying the gateway's OWN status code and body
    verbatim, so the browser's `resp.ok` is correctly `false` and sse.js's
    existing (already-correct) `onBlocked` -> `ApiClient.decode()` ->
    `<ys-verdict-banner>` path fires as designed. 200/201/206 still streams
    through unchanged.

This suite has two halves:
  * chat-view.js — static/structural checks (no JS runtime harness in this
    repo; mirrors the established pattern in test_v50_023_*).
  * user_chat_proxy — a REAL executable unit test that calls the route
    function directly with a fake httpx transport, proving the fixed status
    code / body passthrough behaviourally (not just "the string exists").
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

SRC = Path(__file__).parent.parent.parent.parent / "yashigani"
UI4 = SRC / "backoffice" / "static" / "ui4"
CHAT_VIEW_JS = UI4 / "user" / "chat-view.js"


def _read(path: Path) -> str:
    assert path.is_file(), f"expected file missing: {path}"
    return path.read_text(encoding="utf-8")


def _strip_js_comments(js_source: str) -> str:
    return re.sub(r"//[^\n]*", "", js_source)


# ---------------------------------------------------------------------------
# V50-025 — chat-view.js default-model sync (structural)
# ---------------------------------------------------------------------------

class TestChatViewDefaultModelSync:
    def test_updated_hooks_default_model_sync_on_models_change(self):
        src = _strip_js_comments(_read(CHAT_VIEW_JS))
        m = re.search(r"updated\(changed\)\s*\{(.*?)\n  \}", src, re.S)
        assert m, "updated(changed) lifecycle method not found in chat-view.js"
        body = m.group(1)
        assert "changed.has('models')" in body, (
            "V50-025 regression: updated() no longer reacts to `models` "
            "populating — selectedModel would stay '' forever and the first "
            "Send would target activeAgentId instead of the shown model."
        )
        assert "_syncDefaultModelSelection" in body, (
            "V50-025 regression: updated() no longer calls "
            "_syncDefaultModelSelection() when models arrives."
        )

    def test_sync_default_model_selection_reads_live_select_and_falls_back_to_first(self):
        src = _strip_js_comments(_read(CHAT_VIEW_JS))
        m = re.search(r"_syncDefaultModelSelection\(\)\s*\{(.*?)\n  \}", src, re.S)
        assert m, "_syncDefaultModelSelection() not found"
        body = m.group(1)
        assert "querySelector('.ys-model-select')" in body, (
            "must read the ACTUAL rendered <select>, not re-derive a guess"
        )
        assert "models[0]" in body, "must fall back to the first model entry"
        assert "this.selectedModel = model" in body, (
            "V50-025 regression: must assign the resolved model into "
            "selectedModel so _currentModel()/_targetModel() stop falling "
            "through to activeAgentId."
        )

    def test_sync_default_model_selection_echoes_to_app_like_manual_pick(self):
        """Must dispatch ys-model-select — same event _onModelChange uses —
        so the app (single source of truth per this file's header) stays in
        sync rather than the child silently diverging from parent state."""
        src = _strip_js_comments(_read(CHAT_VIEW_JS))
        m = re.search(r"_syncDefaultModelSelection\(\)\s*\{(.*?)\n  \}", src, re.S)
        assert m
        body = m.group(1)
        assert "ys-model-select" in body

    def test_sync_default_model_selection_is_a_noop_once_selected(self):
        """Guard against re-firing / clobbering an explicit user pick."""
        src = _strip_js_comments(_read(CHAT_VIEW_JS))
        m = re.search(r"_syncDefaultModelSelection\(\)\s*\{(.*?)\n  \}", src, re.S)
        assert m
        body = m.group(1)
        assert "if (this.selectedModel) return;" in body

    def test_current_model_still_prefers_selected_model_first(self):
        """_currentModel()'s precedence contract (selectedModel > activeAgentId
        > 'default') must be unchanged — V50-025's fix is upstream of this
        function (making selectedModel populate promptly), not a change to
        the fallback chain itself."""
        src = _strip_js_comments(_read(CHAT_VIEW_JS))
        m = re.search(r"_currentModel\(\)\s*\{(.*?)\n  \}", src, re.S)
        assert m, "_currentModel() not found"
        assert "this.selectedModel || this.activeAgentId || 'default'" in m.group(1)


# ---------------------------------------------------------------------------
# V50-026 — user_chat_proxy status-code passthrough (executable)
# ---------------------------------------------------------------------------

class _FakeUpstreamResponse:
    """Stands in for the object httpx.AsyncClient.send(..., stream=True)
    returns: headers available immediately, body read lazily."""

    def __init__(self, status_code: int, content: bytes, headers: dict | None = None):
        self.status_code = status_code
        self._content = content
        self.headers = headers or {"content-type": "application/json"}
        self.aclose_called = False

    async def aread(self) -> bytes:
        return self._content

    async def aiter_bytes(self):
        yield self._content

    async def aclose(self):
        self.aclose_called = True


class _FakeAsyncClient:
    """Stands in for httpx.AsyncClient — build_request/send(stream=True)/aclose
    only, matching exactly what user_chat_proxy calls post-fix."""

    def __init__(self, upstream_response: _FakeUpstreamResponse, **_kwargs):
        self._upstream_response = upstream_response
        self.aclose_called = False

    def build_request(self, method, url, content=None, headers=None):
        return SimpleNamespace(method=method, url=url, content=content, headers=headers)

    async def send(self, request, stream=False):
        assert stream is True, "user_chat_proxy must open the gateway request with stream=True"
        return self._upstream_response

    async def aclose(self):
        self.aclose_called = True


class _FakeSession:
    def __init__(self, account_id: str = "550e8400-e29b-41d4-a716-446655440000"):
        self.account_id = account_id


class _FakeRequest:
    def __init__(self, body: bytes = b'{"model":"qwen2.5:3b","messages":[]}'):
        self._body = body

    async def body(self) -> bytes:
        return self._body


def _fake_identity_registry():
    reg = SimpleNamespace()
    reg.get_by_account_id = lambda account_id: {"identity_id": "idnt_test_user"}
    return reg


@pytest.fixture
def ui_mod(monkeypatch):
    import yashigani.backoffice.routes.user_ui as mod

    monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "test-bearer-token")
    monkeypatch.setenv("YASHIGANI_GATEWAY_MESH_URL", "http://gateway:8081/v1")
    monkeypatch.setattr(mod.backoffice_state, "identity_registry", _fake_identity_registry())
    return mod


def _install_fake_client(monkeypatch, ui_mod, upstream_response: _FakeUpstreamResponse) -> _FakeAsyncClient:
    holder: dict = {}

    def _factory(*_a, **_k):
        client = _FakeAsyncClient(upstream_response)
        holder["client"] = client
        return client

    monkeypatch.setattr(ui_mod.httpx, "AsyncClient", _factory)
    return holder


@pytest.mark.asyncio
async def test_pre_stream_403_is_forwarded_with_the_real_status_code(monkeypatch, ui_mod):
    """
    LAURA-V50-COV-001's sibling in this file: the exact V50-026 scenario —
    the gateway mechanically blocks a prompt injection BEFORE streaming opens
    and returns 403 request_injection_blocked. The proxy must hand the
    browser that SAME status code and body, not a 200-wrapped SSE frame.
    """
    error_body = json.dumps({
        "error": {
            "message": "Your message was blocked by the security policy.",
            "type": "request_injection_blocked",
            "code": "prompt_injection_only",
        }
    }).encode("utf-8")
    upstream = _FakeUpstreamResponse(
        403, error_body,
        headers={
            "content-type": "application/json",
            "X-Yashigani-Request-Verdict": "blocked",
        },
    )
    holder = _install_fake_client(monkeypatch, ui_mod, upstream)

    resp = await ui_mod.user_chat_proxy(_FakeRequest(), _FakeSession())

    assert resp.status_code == 403, (
        "V50-026 regression: user_chat_proxy must forward the gateway's REAL "
        f"403, not silently answer 200 — got {resp.status_code}. A 200 here "
        "means sse.js's `!resp.ok` pre-stream onBlocked path can never fire "
        "and the chat UI renders nothing for a mechanically-blocked injection."
    )
    assert resp.body == error_body, (
        "V50-026 regression: the gateway's structured error body must be "
        "forwarded verbatim (as plain JSON), not re-wrapped as an SSE "
        "`data: {...}` frame — the wrapped shape doesn't match "
        "decode.js's decision_codes/user_alert/blocked contract."
    )
    assert "application/json" in resp.media_type
    # Both the upstream response AND the client must be released.
    assert upstream.aclose_called
    assert holder["client"].aclose_called


@pytest.mark.asyncio
async def test_200_success_still_streams_through_unchanged(monkeypatch, ui_mod):
    """Non-regression: the happy path (200 SSE) must still stream, not be
    swallowed by the new status-check branch."""
    sse_chunk = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
    upstream = _FakeUpstreamResponse(200, sse_chunk, headers={"content-type": "text/event-stream"})
    holder = _install_fake_client(monkeypatch, ui_mod, upstream)

    resp = await ui_mod.user_chat_proxy(_FakeRequest(), _FakeSession())

    assert resp.status_code == 200
    assert resp.media_type == "text/event-stream"

    collected = b""
    async for chunk in resp.body_iterator:
        collected += chunk if isinstance(chunk, (bytes, bytearray)) else chunk.encode("utf-8")
    assert collected == sse_chunk
    assert upstream.aclose_called
    assert holder["client"].aclose_called


@pytest.mark.asyncio
async def test_pre_stream_422_is_also_forwarded_with_real_status(monkeypatch, ui_mod):
    """Same class as the 403 case but for a validation error (e.g. an
    unresolvable model) — must not be silently downgraded to 200 either."""
    error_body = json.dumps({"detail": [{"loc": ["body", "model"], "msg": "unknown model"}]}).encode()
    upstream = _FakeUpstreamResponse(422, error_body, headers={"content-type": "application/json"})
    _install_fake_client(monkeypatch, ui_mod, upstream)

    resp = await ui_mod.user_chat_proxy(_FakeRequest(), _FakeSession())

    assert resp.status_code == 422
    assert resp.body == error_body


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
