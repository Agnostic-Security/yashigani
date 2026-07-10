"""
Unit tests — FIND-3.1-INT-AGENT-AUDIT: 502 upstream failure emits audit.

Before the fix, a network error (httpx exception) reaching the upstream
agent URL returned HTTP 502 with no audit event — an OWASP A09 logging
blind-spot on the agent proxy path.

After the fix:
  - upstream unreachable (any exception) → HTTP 502 returned (unchanged)
  - AND an AGENT_UPSTREAM_UNREACHABLE audit event is written (new)
  - audit failure must never affect the 502 response (best-effort guard)
  - error_type is correctly classified: connect_error / timeout / unknown

AUDIT-AGENT-01  502 still returned on upstream exception
AUDIT-AGENT-02  AgentUpstreamUnreachableEvent written on connect error
AUDIT-AGENT-03  AgentUpstreamUnreachableEvent written on timeout
AUDIT-AGENT-04  Unknown exception → error_type="unknown"
AUDIT-AGENT-05  Audit failure does not break the 502 response
AUDIT-AGENT-06  No audit written when audit_writer is None
AUDIT-AGENT-07  EventType.AGENT_UPSTREAM_UNREACHABLE in schema
AUDIT-AGENT-08  AgentUpstreamUnreachableEvent in schema module

Last updated: 2026-06-19T00:00:00+01:00
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


# ---------------------------------------------------------------------------
# AUDIT-AGENT-07: Event type registered in schema
# ---------------------------------------------------------------------------

def test_agent_upstream_unreachable_event_type_in_schema() -> None:
    """AUDIT-AGENT-07: EventType.AGENT_UPSTREAM_UNREACHABLE must exist."""
    from yashigani.audit.schema import EventType

    assert hasattr(EventType, "AGENT_UPSTREAM_UNREACHABLE"), (
        "EventType.AGENT_UPSTREAM_UNREACHABLE missing from audit schema"
    )
    assert EventType.AGENT_UPSTREAM_UNREACHABLE == "AGENT_UPSTREAM_UNREACHABLE"


# ---------------------------------------------------------------------------
# AUDIT-AGENT-08: Dataclass importable from schema
# ---------------------------------------------------------------------------

def test_agent_upstream_unreachable_event_class_importable() -> None:
    """AUDIT-AGENT-08: AgentUpstreamUnreachableEvent must be importable."""
    from yashigani.audit.schema import AgentUpstreamUnreachableEvent, EventType

    evt = AgentUpstreamUnreachableEvent(
        caller_agent_id="caller-a",
        target_agent_id="target-b",
        remainder_path="/v1/query",
        request_id="req-001",
        error_type="connect_error",
    )
    assert evt.event_type == EventType.AGENT_UPSTREAM_UNREACHABLE
    assert evt.caller_agent_id == "caller-a"
    assert evt.target_agent_id == "target-b"
    assert evt.error_type == "connect_error"
    assert evt.masking_applied is True  # security invariant


# ---------------------------------------------------------------------------
# Helpers — build a minimal route_agent_call state dict
# ---------------------------------------------------------------------------

def _make_state(audit_writer=None):
    """Minimal state dict for route_agent_call."""
    config = MagicMock()
    config.opa_url = "http://opa:8181"

    registry = {
        "target-b": {
            "status": "active",
            "upstream_url": "http://127.0.0.1:19999",  # nothing listening here
            "groups": [],
            "allowed_caller_groups": ["any"],
            "allowed_paths": ["**"],
            "sensitivity_ceiling": "RESTRICTED",
        }
    }
    return {
        "agent_registry": registry,
        "audit_writer": audit_writer,
        "config": config,
        "principal_verifier": None,
        "principal_signer": None,
        "principal_tenant_id": "default",
        "response_inspection_pipeline": None,
    }


def _make_request(caller_id: str = "caller-a", path: str = "/agents/target-b/v1/query"):
    """Build a minimal ASGI-like request mock."""
    req = MagicMock()
    req.method = "POST"
    req.headers = {}
    req.state = MagicMock()
    req.state.agent_id = caller_id
    req.state.request_id = "req-test-001"

    async def _body():
        return b'{"prompt": "hello"}'

    req.body = _body
    return req


async def _call_route(exc_to_raise, audit_writer=None):
    """
    Helper: wire route_agent_call with OPA stub + upstream that raises exc.
    Returns (response, audit_writer) so callers can assert on audit calls.
    """
    from yashigani.gateway.agent_router import route_agent_call

    state = _make_state(audit_writer=audit_writer)
    request = _make_request()

    # OPA returns allow=True so we reach the upstream call
    async def _opa_allow(*args, **kwargs):
        return True, ""

    # Client-policy returns allow=True
    async def _cp_allow(*args, **kwargs):
        return {"allow": True, "deny": []}

    # Upstream raises the provided exception
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
    mock_client_instance.__aexit__ = AsyncMock(return_value=False)
    mock_client_instance.request = AsyncMock(side_effect=exc_to_raise)

    with (
        patch("yashigani.gateway.agent_router._opa_agent_check", side_effect=_opa_allow),
        patch("yashigani.gateway.agent_router.evaluate_client_policies", side_effect=_cp_allow),
        patch("httpx.AsyncClient", return_value=mock_client_instance),
    ):
        resp = await route_agent_call(request, "/agents/target-b/v1/query", state)

    return resp


# ---------------------------------------------------------------------------
# AUDIT-AGENT-01: 502 still returned on upstream exception
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_upstream_unreachable_returns_502() -> None:
    """AUDIT-AGENT-01: upstream connect error must still return 502."""
    resp = await _call_route(httpx.ConnectError("connection refused"))
    assert resp.status_code == 502
    import json
    body = json.loads(resp.body)
    assert body["error"] == "AGENT_UPSTREAM_UNREACHABLE"
    assert body["target_agent_id"] == "target-b"


# ---------------------------------------------------------------------------
# AUDIT-AGENT-02: ConnectError → AgentUpstreamUnreachableEvent written
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_connect_error_emits_audit_event() -> None:
    """AUDIT-AGENT-02: ConnectError must emit AgentUpstreamUnreachableEvent."""
    audit_writer = MagicMock()
    await _call_route(httpx.ConnectError("connection refused"), audit_writer=audit_writer)

    audit_writer.write.assert_called_once()
    evt = audit_writer.write.call_args[0][0]

    from yashigani.audit.schema import AgentUpstreamUnreachableEvent, EventType
    assert isinstance(evt, AgentUpstreamUnreachableEvent), (
        f"Expected AgentUpstreamUnreachableEvent, got {type(evt)}"
    )
    assert evt.event_type == EventType.AGENT_UPSTREAM_UNREACHABLE
    assert evt.caller_agent_id == "caller-a"
    assert evt.target_agent_id == "target-b"
    assert evt.error_type == "connect_error"
    assert evt.request_id == "req-test-001"


# ---------------------------------------------------------------------------
# AUDIT-AGENT-03: TimeoutException → error_type="timeout"
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_timeout_emits_audit_with_timeout_type() -> None:
    """AUDIT-AGENT-03: TimeoutException must classify as error_type='timeout'."""
    audit_writer = MagicMock()
    await _call_route(httpx.TimeoutException("read timed out"), audit_writer=audit_writer)

    audit_writer.write.assert_called_once()
    evt = audit_writer.write.call_args[0][0]

    from yashigani.audit.schema import AgentUpstreamUnreachableEvent
    assert isinstance(evt, AgentUpstreamUnreachableEvent)
    assert evt.error_type == "timeout"


# ---------------------------------------------------------------------------
# AUDIT-AGENT-04: Unknown exception → error_type="unknown"
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_exception_uses_unknown_error_type() -> None:
    """AUDIT-AGENT-04: Non-httpx exception → error_type='unknown'."""
    audit_writer = MagicMock()
    await _call_route(RuntimeError("unexpected socket error"), audit_writer=audit_writer)

    audit_writer.write.assert_called_once()
    evt = audit_writer.write.call_args[0][0]

    from yashigani.audit.schema import AgentUpstreamUnreachableEvent
    assert isinstance(evt, AgentUpstreamUnreachableEvent)
    assert evt.error_type == "unknown"


# ---------------------------------------------------------------------------
# AUDIT-AGENT-05: Audit failure does not break the 502 response
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_audit_failure_does_not_break_502() -> None:
    """AUDIT-AGENT-05: If audit_writer.write raises, the 502 must still be returned."""
    audit_writer = MagicMock()
    audit_writer.write.side_effect = RuntimeError("audit sink is down")

    resp = await _call_route(httpx.ConnectError("refused"), audit_writer=audit_writer)
    # The 502 must still come back even when the audit write explodes
    assert resp.status_code == 502


# ---------------------------------------------------------------------------
# AUDIT-AGENT-06: No audit when audit_writer is None
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_audit_writer_no_crash() -> None:
    """AUDIT-AGENT-06: No audit_writer → no crash, 502 still returned."""
    resp = await _call_route(httpx.ConnectError("refused"), audit_writer=None)
    assert resp.status_code == 502
