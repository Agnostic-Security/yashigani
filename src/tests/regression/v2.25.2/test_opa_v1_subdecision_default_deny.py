"""
v2.25.2 — OPA-003/004 inverted-default cascade closure.

`_opa_v1_check` in openai_router.py parsed three OPA sub-decision fields
with a permissive `True` default on undefined:

    "model_allowed":       bool(result.get("model_allowed", True)),
    "routing_safe":        bool(result.get("routing_safe", True)),
    "sensitivity_allowed": bool(result.get("sensitivity_allowed", True)),

On a bundle-mismatch (e.g. the OPA-002 missing-mcp.rego class), the OPA
response omits these fields, so they silently resolved to PASS. This is the
same fail-open class closed at proxy.py:1127 and in v1_routing.rego
default-deny. The fix flips all three defaults to `False` (fail-closed).
The primary `allow` field was already correctly defaulted to False.

These tests would re-fail on the original `True` defaults.

ASVS V8.* / feedback_zero_trust_default.md / LIFESPAN/SOP-1 fail-closed.

Last updated: 2026-06-04T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _reset_router_state():
    from yashigani.gateway import openai_router as _mod
    _mod._state.opa_url = "https://policy:8181"
    _mod._state.audit_writer = None


def _make_async_client_mock(post_return):
    """Async context manager mock for internal_httpx_client returning post_return."""
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=post_return)
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _opa_response_with(result: dict):
    """Build a mock httpx response whose .json() returns {'result': result}."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock(return_value=None)
    resp.json = MagicMock(return_value={"result": result})
    return resp


async def _run_v1_check():
    from yashigani.gateway import openai_router as _mod
    return await _mod._opa_v1_check(
        identity={"identity_id": "alice", "kind": "human"},
        selected_model="gpt-4o",
        selected_provider="openai",
        sensitivity_level="PUBLIC",
        route_reason="default",
        request_path="/v1/chat/completions",
    )


class TestOpaV1SubDecisionDefaultDeny:
    """OPA-003/004: undefined sub-decisions must default to DENY (False)."""

    @pytest.mark.asyncio
    async def test_undefined_subdecisions_default_false(self):
        """Bundle-mismatch: OPA omits all three sub-fields → all False."""
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()

        # Simulate a bundle-mismatch: allow present, but the three sub-fields
        # are NOT in the OPA result document.
        cm = _make_async_client_mock(
            _opa_response_with({"allow": True, "reason": "ok"})
        )
        with patch.object(_mod, "internal_httpx_client", return_value=cm):
            result = await _run_v1_check()

        assert result["model_allowed"] is False, "undefined model_allowed must fail-closed"
        assert result["routing_safe"] is False, "undefined routing_safe must fail-closed"
        assert result["sensitivity_allowed"] is False, "undefined sensitivity_allowed must fail-closed"

    @pytest.mark.asyncio
    async def test_empty_result_all_subdecisions_false(self):
        """Empty OPA result → allow False AND all sub-decisions False."""
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()

        cm = _make_async_client_mock(_opa_response_with({}))
        with patch.object(_mod, "internal_httpx_client", return_value=cm):
            result = await _run_v1_check()

        assert result["allow"] is False
        assert result["model_allowed"] is False
        assert result["routing_safe"] is False
        assert result["sensitivity_allowed"] is False

    @pytest.mark.asyncio
    async def test_explicit_true_subdecisions_preserved(self):
        """When OPA explicitly returns True for sub-fields, they are honoured."""
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()

        cm = _make_async_client_mock(
            _opa_response_with({
                "allow": True,
                "model_allowed": True,
                "routing_safe": True,
                "sensitivity_allowed": True,
                "reason": "ok",
            })
        )
        with patch.object(_mod, "internal_httpx_client", return_value=cm):
            result = await _run_v1_check()

        assert result["allow"] is True
        assert result["model_allowed"] is True
        assert result["routing_safe"] is True
        assert result["sensitivity_allowed"] is True

    @pytest.mark.asyncio
    async def test_explicit_false_subdecisions_preserved(self):
        """Explicit False sub-decisions stay False (not flipped)."""
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()

        cm = _make_async_client_mock(
            _opa_response_with({
                "allow": False,
                "model_allowed": False,
                "routing_safe": False,
                "sensitivity_allowed": False,
                "reason": "model_denied",
            })
        )
        with patch.object(_mod, "internal_httpx_client", return_value=cm):
            result = await _run_v1_check()

        assert result["allow"] is False
        assert result["model_allowed"] is False
        assert result["routing_safe"] is False
        assert result["sensitivity_allowed"] is False
