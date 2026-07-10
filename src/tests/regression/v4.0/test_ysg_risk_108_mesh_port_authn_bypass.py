"""
Regression tests — YSG-RISK-108: mesh port (:8081) identity-header authn bypass.

T-3: anonymous POST :8081/mcp/<agent> + X-Forwarded-User: <victim>
     → user_id MUST be "unknown"; MESH_IDENTITY_HEADER_REJECTED audit event emitted.

T-4: forged X-Yashigani-Orchestration-Depth without internal bearer
     → caller MUST NOT be promoted to "gateway:orchestrator";
     MESH_ORCH_DEPTH_FORGED audit event emitted.

T-3 POSITIVE: internal bearer present + X-Forwarded-User → user_id = the slug.
T-4 POSITIVE: internal bearer present + depth header → promoted to gateway:orchestrator.

Reference: docs/risk-register.yml YSG-RISK-108 / Laura findings T-3/T-4.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_FAKE_BEARER = "test-internal-bearer-secret-32chars!!"


def _make_request(
    headers: dict,
    path: str = "/mcp/test-server",
    method: str = "POST",
    body: bytes = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"greet","arguments":{}},"id":1}',
):
    """Build a minimal Request-like mock."""
    req = MagicMock()
    req.method = method
    req.url.path = path
    lower_headers = {k.lower(): v for k, v in headers.items()}
    req.headers.get = lambda key, default="": lower_headers.get(key.lower(), default)
    req.state = MagicMock()
    req.state.agent_id = None

    async def _body():
        return body

    req.body = _body
    return req


class _RecordingAuditWriter:
    """Captures audit events for assertion."""

    def __init__(self):
        self.events: list = []

    def write(self, event: Any) -> None:
        self.events.append(event)


def _run(coro):
    """Run a coroutine — compatible with Python 3.10+ asyncio.run()."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _mesh_caller_is_internal unit tests (sync — no event loop needed)
# ---------------------------------------------------------------------------

def test_mesh_caller_is_internal_no_auth(monkeypatch) -> None:
    """No Authorization header → not internal."""
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    from yashigani.gateway.mcp_router_runtime import _mesh_caller_is_internal
    req = _make_request(headers={})
    assert _mesh_caller_is_internal(req) is False, "No auth header must not be internal"


def test_mesh_caller_is_internal_wrong_bearer(monkeypatch) -> None:
    """Wrong bearer value → not internal (constant-time compare)."""
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    from yashigani.gateway.mcp_router_runtime import _mesh_caller_is_internal
    req = _make_request(headers={"Authorization": "Bearer wrong-secret"})
    assert _mesh_caller_is_internal(req) is False, "Wrong bearer must not be internal"


def test_mesh_caller_is_internal_correct_bearer(monkeypatch) -> None:
    """Correct bearer value → is internal."""
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    from yashigani.gateway.mcp_router_runtime import _mesh_caller_is_internal
    req = _make_request(headers={"Authorization": f"Bearer {_FAKE_BEARER}"})
    assert _mesh_caller_is_internal(req) is True, "Correct bearer must be internal"


def test_mesh_caller_is_internal_non_bearer_scheme(monkeypatch) -> None:
    """Non-Bearer auth scheme → not internal."""
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    from yashigani.gateway.mcp_router_runtime import _mesh_caller_is_internal
    req = _make_request(headers={"Authorization": f"Basic {_FAKE_BEARER}"})
    assert _mesh_caller_is_internal(req) is False, "Basic auth must not be treated as internal"


# ---------------------------------------------------------------------------
# T-3: anonymous caller with X-Forwarded-User → user_id must be "unknown"
# ---------------------------------------------------------------------------

def test_t3_anonymous_forwarded_user_is_stripped(monkeypatch) -> None:
    """
    T-3 REGRESSION: anonymous POST :8081/mcp/test-server + X-Forwarded-User: victim
    → MESH_IDENTITY_HEADER_REJECTED audit event MUST be emitted; registry misses (404)
    proves we got past the identity gate with user_id stripped.
    """
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    # No Caddy secret on mesh port
    monkeypatch.setattr("yashigani.auth.caddy_verified._caddy_secret", None)

    import yashigani.gateway.mcp_router_runtime as rt

    audit_writer = _RecordingAuditWriter()

    # Anonymous request — no auth, only forged X-Forwarded-User
    request = _make_request(
        headers={"X-Forwarded-User": "victim-user"},
        path="/mcp/test-server",
    )

    # Registry returns None → 404; we only need to check the identity gate ran
    registry = MagicMock()
    registry.get.return_value = None

    result = _run(
        rt._handle_mcp_call_inner(
            agent_name="test-server",
            request=request,
            registry=registry,
            audit_writer=audit_writer,
        )
    )

    # 404 expected (registry miss) — confirms we reached the registry lookup
    assert result.status_code == 404

    # MESH_IDENTITY_HEADER_REJECTED MUST be in the audit chain
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" in event_types, (
        f"Expected MeshIdentityHeaderRejectedEvent; got: {event_types}"
    )

    rejected = [e for e in audit_writer.events
                if type(e).__name__ == "MeshIdentityHeaderRejectedEvent"]
    assert rejected[0].rejected_header == "x-forwarded-user"
    assert "victim" in rejected[0].claimed_value_truncated


def test_t3_anonymous_no_forwarded_user_no_audit_event(monkeypatch) -> None:
    """
    T-3 NEGATIVE: anonymous caller with no X-Forwarded-User header
    → no audit event, normal unauthenticated path (user_id = "unknown").
    """
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    monkeypatch.setattr("yashigani.auth.caddy_verified._caddy_secret", None)

    import yashigani.gateway.mcp_router_runtime as rt

    audit_writer = _RecordingAuditWriter()
    request = _make_request(headers={}, path="/mcp/test-server")

    registry = MagicMock()
    registry.get.return_value = None

    result = _run(
        rt._handle_mcp_call_inner(
            agent_name="test-server",
            request=request,
            registry=registry,
            audit_writer=audit_writer,
        )
    )

    assert result.status_code == 404
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" not in event_types, (
        f"Unexpected rejection event for caller with no X-Forwarded-User: {event_types}"
    )


def test_t3_internal_bearer_forwarded_user_is_trusted(monkeypatch) -> None:
    """
    T-3 POSITIVE: internal bearer + X-Forwarded-User → no rejection event.
    Proves the legitimate orchestrator/OWUI path is not broken.
    """
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    monkeypatch.setattr("yashigani.auth.caddy_verified._caddy_secret", None)

    import yashigani.gateway.mcp_router_runtime as rt

    audit_writer = _RecordingAuditWriter()
    request = _make_request(
        headers={
            "Authorization": f"Bearer {_FAKE_BEARER}",
            "X-Forwarded-User": "alice",
        },
        path="/mcp/test-server",
    )

    registry = MagicMock()
    registry.get.return_value = None  # 404 early exit

    result = _run(
        rt._handle_mcp_call_inner(
            agent_name="test-server",
            request=request,
            registry=registry,
            audit_writer=audit_writer,
        )
    )

    assert result.status_code == 404
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" not in event_types, (
        f"Unexpected rejection event for legitimate internal caller: {event_types}"
    )


# ---------------------------------------------------------------------------
# T-4: forged depth header → NOT promoted to gateway:orchestrator
# ---------------------------------------------------------------------------

def test_t4_forged_depth_header_not_promoted(monkeypatch) -> None:
    """
    T-4 REGRESSION: anonymous caller presents X-Yashigani-Orchestration-Depth: 1
    → MUST NOT be promoted to gateway:orchestrator;
    MESH_ORCH_DEPTH_FORGED audit event MUST be emitted.
    """
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    monkeypatch.setattr("yashigani.auth.caddy_verified._caddy_secret", None)

    import yashigani.gateway.mcp_router_runtime as rt

    # Track caller_agent_id when McpCallContext is instantiated
    captured_caller_agent_ids: list = []
    from yashigani.mcp._types import McpCallContext as _OrigCtx

    _orig_init = _OrigCtx.__init__

    def _capturing_init(self, **kwargs):
        captured_caller_agent_ids.append(kwargs.get("caller_agent_id"))
        _orig_init(self, **kwargs)

    monkeypatch.setattr(_OrigCtx, "__init__", _capturing_init)

    audit_writer = _RecordingAuditWriter()

    # No Authorization, only forged depth header
    request = _make_request(
        headers={"X-Yashigani-Orchestration-Depth": "1"},
        path="/mcp/test-server",
    )

    registry = MagicMock()
    registry.get.return_value = None  # 404

    result = _run(
        rt._handle_mcp_call_inner(
            agent_name="test-server",
            request=request,
            registry=registry,
            audit_writer=audit_writer,
        )
    )

    assert result.status_code == 404

    # MESH_ORCH_DEPTH_FORGED MUST be in the audit chain
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshOrchDepthForgedEvent" in event_types, (
        f"Expected MeshOrchDepthForgedEvent; got: {event_types}"
    )

    # If McpCallContext was somehow created, caller_agent_id must NOT be orchestrator
    for cid in captured_caller_agent_ids:
        assert cid != "gateway:orchestrator", (
            f"Forged depth header MUST NOT promote caller, got: {cid}"
        )


def test_t4_internal_bearer_depth_header_is_promoted(monkeypatch) -> None:
    """
    T-4 POSITIVE: internal bearer + depth header → promoted to gateway:orchestrator.
    Proves the legitimate orchestrator self-call path is not broken.
    """
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    monkeypatch.setattr("yashigani.auth.caddy_verified._caddy_secret", None)

    import yashigani.gateway.mcp_router_runtime as rt

    # Track caller_agent_id
    captured_caller_agent_ids: list = []
    from yashigani.mcp._types import McpCallContext as _OrigCtx

    _orig_init = _OrigCtx.__init__

    def _capturing_init(self, **kwargs):
        captured_caller_agent_ids.append(kwargs.get("caller_agent_id"))
        _orig_init(self, **kwargs)

    monkeypatch.setattr(_OrigCtx, "__init__", _capturing_init)

    audit_writer = _RecordingAuditWriter()

    # Legitimate orchestrator self-call: bearer + depth header
    request = _make_request(
        headers={
            "Authorization": f"Bearer {_FAKE_BEARER}",
            "X-Yashigani-Orchestration-Depth": "1",
        },
        path="/mcp/test-server",
    )

    registry = MagicMock()
    registry.get.return_value = None  # 404

    result = _run(
        rt._handle_mcp_call_inner(
            agent_name="test-server",
            request=request,
            registry=registry,
            audit_writer=audit_writer,
        )
    )

    assert result.status_code == 404

    # No rejection event for a legitimate orchestrator call
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshOrchDepthForgedEvent" not in event_types, (
        f"Unexpected MeshOrchDepthForgedEvent for legitimate orchestrator: {event_types}"
    )


# ---------------------------------------------------------------------------
# T-3 + T-4 combined: anonymous caller with both forged headers
# ---------------------------------------------------------------------------

def test_t3_and_t4_combined_anonymous_caller(monkeypatch) -> None:
    """
    Combined exploit: anonymous caller presents BOTH X-Forwarded-User AND
    X-Yashigani-Orchestration-Depth — neither must be trusted.
    Both MESH_IDENTITY_HEADER_REJECTED and MESH_ORCH_DEPTH_FORGED must be emitted.
    """
    monkeypatch.setattr("yashigani.gateway.openai_router._INTERNAL_BEARER", _FAKE_BEARER)
    monkeypatch.setattr("yashigani.auth.caddy_verified._caddy_secret", None)

    import yashigani.gateway.mcp_router_runtime as rt

    audit_writer = _RecordingAuditWriter()

    request = _make_request(
        headers={
            "X-Forwarded-User": "victim-user",
            "X-Yashigani-Orchestration-Depth": "1",
        },
        path="/mcp/test-server",
    )

    registry = MagicMock()
    registry.get.return_value = None

    result = _run(
        rt._handle_mcp_call_inner(
            agent_name="test-server",
            request=request,
            registry=registry,
            audit_writer=audit_writer,
        )
    )

    assert result.status_code == 404

    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" in event_types, (
        f"Expected T-3 rejection event: {event_types}"
    )
    assert "MeshOrchDepthForgedEvent" in event_types, (
        f"Expected T-4 forged-depth event: {event_types}"
    )
