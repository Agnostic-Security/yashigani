"""
Shared pytest fixtures for Yashigani unit tests.

Fixtures cover the three main I/O boundaries:
  - Redis (via fakeredis)
  - OPA (via httpx MockTransport)
  - Upstream MCP / Ollama (via httpx MockTransport)

Last updated: 2026-04-27T21:08:49+01:00
"""
from __future__ import annotations

# LAURA-V231-004: set YASHIGANI_ENV=dev before any yashigani.licensing imports.
# The licensing verifier runs _check_self_integrity() at module load; without
# this line CI (which does not set YASHIGANI_ENV) would trigger the
# _integrity_violated flag for every test that imports verifier, causing 17+
# tests to fail with COMMUNITY-tier results instead of their expected values.
# setdefault() preserves any explicit override already present in the environment.
import os
os.environ.setdefault("YASHIGANI_ENV", "dev")

# YSG-TEST-BEARER: set YASHIGANI_INTERNAL_BEARER before any gateway module import.
# gateway/proxy.py and gateway/openai_router.py execute _load_internal_bearer() at
# module load time (fail-closed production behaviour). Without a value, the first
# import raises RuntimeError and pollutes sys.modules, causing cascading failures
# across ALL unit tests that import any gateway module even indirectly.
# setdefault() preserves an explicit override (e.g. CI with a real rotated secret).
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-unit-tests")

# YSG-TEST-OPA-OPTIONAL: allow tests to run without a live OPA instance.
# Tests that need OPA enforcement use MockOPATransport or patch opa_url directly.
# Without this flag the router's _opa_v1_check is fail-closed (correct for
# production) but causes all unit tests without a real OPA to 403 on every call.
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")

import json
import pytest
from unittest.mock import MagicMock, AsyncMock
import httpx


# ---------------------------------------------------------------------------
# Marker registration
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: marks integration tests (deselect with '-m \"not integration\"')",
    )


# ---------------------------------------------------------------------------
# Redis fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_redis():
    """Synchronous fakeredis client. Use for RBACStore, RateLimiter."""
    try:
        import fakeredis
        client = fakeredis.FakeRedis(decode_responses=False)
        yield client
        client.flushall()
    except ImportError:
        import warnings
        warnings.warn(
            "fakeredis not installed — Redis-dependent tests will be skipped. "
            "Run: pip install 'yashigani[dev]'",
            stacklevel=2,
        )


@pytest.fixture
async def async_mock_redis():
    """Async fakeredis client. Use for async Redis operations."""
    try:
        import fakeredis.aioredis
        client = fakeredis.aioredis.FakeRedis(decode_responses=False)
        yield client
        await client.flushall()
        await client.aclose()
    except ImportError:
        import warnings
        warnings.warn(
            "fakeredis not installed — Redis-dependent tests will be skipped. "
            "Run: pip install 'yashigani[dev]'",
            stacklevel=2,
        )


# ---------------------------------------------------------------------------
# OPA mock transport
# ---------------------------------------------------------------------------

class MockOPATransport(httpx.MockTransport):
    """
    httpx transport that mimics OPA /v1/data/yashigani responses.
    Default: allow=True. Call set_decision("deny") to flip.
    """
    def __init__(self, allow: bool = True):
        self._allow = allow

    def set_decision(self, decision: str) -> None:
        self._allow = decision != "deny"

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/v1/data"):
            body = {"result": {"allow": self._allow, "deny": not self._allow}}
            return httpx.Response(200, json=body)
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404, json={"error": "not_found"})


@pytest.fixture
def mock_opa():
    transport = MockOPATransport(allow=True)
    yield transport


# ---------------------------------------------------------------------------
# Ollama mock transport
# ---------------------------------------------------------------------------

CANNED_CLEAN_RESPONSE = json.dumps({
    "label": "CLEAN",
    "confidence": 0.97,
    "reasoning": "No injection patterns detected."
})

CANNED_INJECTION_RESPONSE = json.dumps({
    "label": "PROMPT_INJECTION_ONLY",
    "confidence": 0.93,
    "reasoning": "Detected ignore-previous-instructions pattern."
})


class MockOllamaTransport(httpx.MockTransport):
    def __init__(self, label: str = "CLEAN", confidence: float = 0.97):
        self._label = label
        self._confidence = confidence

    def set_response(self, label: str, confidence: float = 0.9) -> None:
        self._label = label
        self._confidence = confidence

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if "/api/generate" in request.url.path or "/api/chat" in request.url.path:
            resp = json.dumps({"label": self._label, "confidence": self._confidence, "reasoning": "mock"})
            return httpx.Response(200, json={
                "model": "qwen2.5:3b",
                "response": resp,
                "done": True,
            })
        if "/api/tags" in request.url.path:
            return httpx.Response(200, json={"models": [{"name": "qwen2.5:3b"}]})
        return httpx.Response(404)


@pytest.fixture
def mock_ollama():
    yield MockOllamaTransport()


# ---------------------------------------------------------------------------
# Upstream MCP mock
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_upstream():
    """Returns a 200 OK from the upstream MCP server."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": "ok"})
    return httpx.MockTransport(handler=handler)


# ---------------------------------------------------------------------------
# Audit writer mock
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_audit_writer():
    writer = MagicMock()
    writer.write = MagicMock()
    return writer
