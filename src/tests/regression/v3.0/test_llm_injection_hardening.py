"""
Regression tests — LAURA-2255-003/004 / 30-007/008: LLM injection hardening.

Verifies:
  1. generate_pattern uses /api/chat (not /api/generate).
  2. generate_pattern does NOT return raw_llm_response to the client.
  3. opa_assistant generator uses /api/chat (not /api/generate).
  4. SuggestResponse schema has no raw_response field.
  5. opa_assistant route does NOT pass raw_response to client.
  6. generate_pattern with unsafe AI regex → regex suppressed (not returned).
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_session():
    from yashigani.auth.session import Session
    now = time.time()
    return Session(
        token="t",
        account_id="admin",
        account_tier="admin",
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="127.0.0",
        last_totp_verified_at=now,
    )


def _make_sensitivity_app():
    app = FastAPI()
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice.routes.sensitivity import router

    session = _fake_session()
    app.dependency_overrides[require_admin_session] = lambda: session
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# 1. generate_pattern: must call /api/chat, not /api/generate
# ---------------------------------------------------------------------------

def test_generate_pattern_uses_chat_api():
    """LAURA-2255-003: generate_pattern uses chat API (system+user roles)."""
    from yashigani.backoffice.routes.sensitivity import generate_pattern
    import inspect
    src = inspect.getsource(generate_pattern)
    assert "/api/chat" in src, "generate_pattern must call /api/chat (not /api/generate)"
    assert "/api/generate" not in src, (
        "generate_pattern must NOT call /api/generate (injection hardening)"
    )


# ---------------------------------------------------------------------------
# 2. generate_pattern: does NOT return raw_llm_response to client
# ---------------------------------------------------------------------------

def test_generate_pattern_no_raw_response_key():
    """LAURA-2255-003: generate_pattern response must not contain raw_llm_response."""
    app = _make_sensitivity_app()

    good_payload = json.dumps({
        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "level": 4,
        "description": "US SSN",
    })

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"message": {"content": good_payload}}
    mock_resp.raise_for_status = MagicMock()

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, *a, **kw):
            r = MagicMock()
            r.json.return_value = {"models": [{"name": "qwen2.5:3b"}]}
            return r
        async def post(self, *a, **kw): return mock_resp

    with patch("yashigani.backoffice.routes.sensitivity._httpx.AsyncClient", return_value=_FakeClient()):
        with TestClient(app) as c:
            resp = c.post("/generate-pattern", json={"description": "US Social Security Numbers"})

    assert resp.status_code == 200
    data = resp.json()
    assert "raw_llm_response" not in data, (
        "LAURA-2255-003 REGRESSION: raw_llm_response must not be returned to the client"
    )
    assert "generated_regex" in data


# ---------------------------------------------------------------------------
# 3. OPAAssistantGenerator: must call /api/chat, not /api/generate
# ---------------------------------------------------------------------------

def test_opa_assistant_generator_uses_chat_api():
    """LAURA-2255-004: OPAAssistantGenerator uses /api/chat."""
    import inspect
    from yashigani.opa_assistant.generator import OPAAssistantGenerator
    src = inspect.getsource(OPAAssistantGenerator.generate)
    assert "/api/chat" in src, "OPAAssistantGenerator.generate must call /api/chat"
    assert "/api/generate" not in src, (
        "OPAAssistantGenerator.generate must NOT call /api/generate"
    )


# ---------------------------------------------------------------------------
# 4. SuggestResponse: no raw_response field in schema
# ---------------------------------------------------------------------------

def test_suggest_response_no_raw_response_field():
    """LAURA-2255-004: SuggestResponse schema must not have raw_response."""
    from yashigani.backoffice.routes.opa_assistant import SuggestResponse
    fields = SuggestResponse.model_fields
    assert "raw_response" not in fields, (
        "LAURA-2255-004 REGRESSION: SuggestResponse still has raw_response field — "
        "raw LLM output must not be returned to the client"
    )


# ---------------------------------------------------------------------------
# 5. OPAAssistantGenerator.generate: no raw_response in return value
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_opa_assistant_generator_no_raw_response_in_return():
    """LAURA-2255-004: OPAAssistantGenerator.generate does not return raw_response."""
    from yashigani.opa_assistant.generator import OPAAssistantGenerator

    rbac_doc = {"groups": {"g": {"id": "g", "display_name": "G", "allowed_resources": []}}, "user_groups": {}}
    rbac_json = json.dumps(rbac_doc)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"message": {"content": rbac_json}}
    mock_resp.raise_for_status = MagicMock()

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **kw): return mock_resp

    with patch("yashigani.opa_assistant.generator.httpx.AsyncClient", return_value=_FakeClient()):
        gen = OPAAssistantGenerator()
        result = await gen.generate("allow engineering access to /tools/**")

    assert "raw_response" not in result, (
        "LAURA-2255-004 REGRESSION: OPAAssistantGenerator.generate still returns "
        "raw_response — remove it from the return dict"
    )
    assert result.get("valid") is True
    assert result.get("suggestion") is not None


# ---------------------------------------------------------------------------
# 6. generate_pattern: unsafe AI-generated regex is suppressed
# ---------------------------------------------------------------------------

def test_generate_pattern_unsafe_ai_regex_suppressed():
    """LAURA-2255-003: AI-generated regex that fails safety validation is cleared."""
    app = _make_sensitivity_app()

    # LLM returns a trivially-overbroad pattern (.*) — should be suppressed
    overbroad_payload = json.dumps({
        "regex": ".*",
        "level": 3,
        "description": "Anything",
    })

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"message": {"content": overbroad_payload}}
    mock_resp.raise_for_status = MagicMock()

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, *a, **kw):
            r = MagicMock()
            r.json.return_value = {"models": [{"name": "qwen2.5:3b"}]}
            return r
        async def post(self, *a, **kw): return mock_resp

    with patch("yashigani.backoffice.routes.sensitivity._httpx.AsyncClient", return_value=_FakeClient()):
        with TestClient(app) as c:
            resp = c.post("/generate-pattern", json={"description": "anything at all"})

    assert resp.status_code == 200
    data = resp.json()
    # The overbroad regex should have been suppressed
    assert data.get("generated_regex", "") == "", (
        "LAURA-2255-003: overbroad AI-generated regex '.*' should be suppressed "
        f"(cleared), but got: {data.get('generated_regex')!r}"
    )
    assert data.get("status") == "parse_error"
