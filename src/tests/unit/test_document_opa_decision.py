"""
Deterministic gate — evaluate_document_decision() fail-closed contract (2.26).

The async real-OPA client must NEVER fail open: any OPA error / timeout / missing
result / malformed decision → a synthetic BLOCK decision.

Author: Tom. Last updated: 2026-06-09.
"""
from __future__ import annotations

import pytest

from yashigani.documents import opa_decision


@pytest.mark.asyncio
async def test_opa_unreachable_fails_closed(monkeypatch):
    """A connection error → fail-closed BLOCK decision (never an exception)."""
    class _BoomClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, *a, **k):
            raise ConnectionError("opa down")

    monkeypatch.setattr(opa_decision, "internal_httpx_client", lambda **k: _BoomClient())
    d = await opa_decision.evaluate_document_decision("https://policy:8181", {"format": "txt"})
    assert d["action"] == "BLOCK"
    assert d["allow"] is False
    assert "opa_unavailable" in d["deny"]
    assert d["code"] == "DOCUMENT_BLOCKED"


@pytest.mark.asyncio
async def test_malformed_result_fails_closed(monkeypatch):
    """OPA returns an unknown action → fail-closed BLOCK."""
    class _Resp:
        def raise_for_status(self):
            return None
        def json(self):
            return {"result": {"action": "FORWARD_EVERYTHING"}}

    class _Client:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(opa_decision, "internal_httpx_client", lambda **k: _Client())
    d = await opa_decision.evaluate_document_decision("https://policy:8181", {"format": "txt"})
    assert d["action"] == "BLOCK"


@pytest.mark.asyncio
async def test_valid_decision_passes_through(monkeypatch):
    """A well-formed OPA decision is returned verbatim."""
    decision = {
        "action": "PSEUDONYMIZE", "allow": True, "deny": [],
        "obligations": ["apply_pseudonymize_tokens"], "policy_id": "DOC-ENFORCE-001",
        "code": "DOCUMENT_PII_PSEUDONYMIZED", "user_message": "ok",
    }

    class _Resp:
        def raise_for_status(self):
            return None
        def json(self):
            return {"result": decision}

    class _Client:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(opa_decision, "internal_httpx_client", lambda **k: _Client())
    d = await opa_decision.evaluate_document_decision(
        "https://policy:8181", {"format": "xlsx"}, route="egress-mcp-result", pseudonymize_mode="A"
    )
    assert d["action"] == "PSEUDONYMIZE"
    assert d["obligations"] == ["apply_pseudonymize_tokens"]
