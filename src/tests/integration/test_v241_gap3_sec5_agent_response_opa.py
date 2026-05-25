"""
v2.24.1 — GAP-3 / SEC-5: Integration tests for agent-router response OPA check.

Covers the two prescribed integration scenarios:
  A. Low-clearance caller agent → target returns CONFIDENTIAL response → caller gets 403,
     audit event AGENT_RESPONSE_BLOCKED_BY_OPA written.
  B. Same flow but response is PUBLIC → caller gets 200.

These tests use in-memory fakes (no live OPA, no live upstream agent) with
mocked httpx to avoid network dependencies.  The OPA logic itself is
validated by unit tests in test_v241_gap3_sec5_response_sensitivity.py
(Section 5 — Rego rule logic) and by live Rego evaluation in the evidence dir.

No Docker/Podman required.  Marked as integration because they exercise the
full agent_router.route_agent_call() function end-to-end.

ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3 / Iris SEC-5 / Ava GAP-3
Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_registry(
    caller_agent_id: str,
    target_agent_id: str,
    caller_ceiling: str = "PUBLIC",
) -> MagicMock:
    """In-memory agent registry."""
    registry = MagicMock()
    agents = {
        target_agent_id: {
            "agent_id": target_agent_id,
            "status": "active",
            "upstream_url": "http://fake-upstream:9999",
            "allowed_caller_groups": ["grp1"],
            "allowed_paths": ["**"],
        },
        caller_agent_id: {
            "agent_id": caller_agent_id,
            "status": "active",
            "groups": ["grp1"],
            "sensitivity_ceiling": caller_ceiling,
        },
    }
    registry.get = lambda agent_id: agents.get(agent_id)
    return registry


def _make_request(
    caller_agent_id: str,
    target_agent_id: str,
    request_id: str = "req-integ-001",
) -> MagicMock:
    """Minimal FastAPI Request mock."""
    req = MagicMock()
    req.method = "POST"
    req.state = MagicMock()
    req.state.agent_id = caller_agent_id
    req.state.request_id = request_id
    req.headers = {}
    req.body = AsyncMock(return_value=b'{"messages": [{"role": "user", "content": "hello"}]}')
    return req


def _make_config(opa_url: str = "https://policy:8181") -> MagicMock:
    config = MagicMock()
    config.opa_url = opa_url
    return config


def _make_audit_writer() -> MagicMock:
    writer = MagicMock()
    writer.write = MagicMock()
    return writer


def _make_opa_client_mock(allow: bool, reason: str = "ok"):
    """Mock httpx client: first call (agent_call_allowed) → True, second call (agent_response_decision) → allow."""
    call_count = 0

    async def _post(url, json=None, headers=None, **kwargs):
        nonlocal call_count
        call_count += 1
        if "agent_call_allowed" in url:
            # Request-leg check — always allow so we reach the response check
            result = {"result": True}
        else:
            # Response-leg check — return the configured allow/reason
            result = {"result": {"allow": allow, "reason": reason}}
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value=result)
        return resp

    mock_client = AsyncMock()
    mock_client.post = _post

    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_upstream_response(content_type: str, body: str, status: int = 200) -> MagicMock:
    """Mock httpx upstream response."""
    resp = MagicMock()
    resp.status_code = status
    resp.content = body.encode("utf-8")
    resp.text = body
    # Use a MagicMock for headers so we can add a .get() method
    headers_mock = MagicMock()
    _hdr_data = {"content-type": content_type}
    headers_mock.get = lambda k, default=None: _hdr_data.get(k, default)
    headers_mock.items = lambda: _hdr_data.items()
    resp.headers = headers_mock
    return resp


def _make_httpx_client_with_upstream(upstream_resp) -> MagicMock:
    """Mock AsyncClient that returns the upstream response."""
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=upstream_resp)

    class _FakeCM:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, *a):
            return False

    return _FakeCM(), mock_client


# ---------------------------------------------------------------------------
# Scenario A: Low-clearance caller, CONFIDENTIAL response → 403
# ---------------------------------------------------------------------------

class TestAgentRouterResponseOPAIntegration:

    @pytest.mark.asyncio
    async def test_scenario_a_confidential_response_blocked_for_low_clearance_caller(self):
        """
        Scenario A: low-clearance caller (PUBLIC ceiling) calls target agent that
        returns CONFIDENTIAL content → OPA blocks → HTTP 403 + audit event written.
        """
        from yashigani.gateway.agent_router import route_agent_call

        caller_id = "agent-low-clearance"
        target_id = "agent-data-store"

        registry = _make_registry(
            caller_agent_id=caller_id,
            target_agent_id=target_id,
            caller_ceiling="PUBLIC",
        )
        request = _make_request(caller_id, target_id)
        config = _make_config()
        audit_writer = _make_audit_writer()

        # Fake upstream returns a CONFIDENTIAL response (contains SSN)
        upstream_body = "The account holder SSN is 123-45-6789. Balance: $10,000."
        upstream_resp = _make_upstream_response("text/plain", upstream_body)

        # Response inspection pipeline: classifies response as CONFIDENTIAL
        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionConfig, ResponseInspectionResult
        mock_pipeline = MagicMock(spec=ResponseInspectionPipeline)
        mock_pipeline.inspect.return_value = ResponseInspectionResult(
            request_id="req-integ-001",
            verdict="CLEAN",
            confidence=0.99,
            skipped=False,
            skip_reason=None,
            audit_fields={},
            response_sensitivity="CONFIDENTIAL",
        )

        # OPA: request-leg allows, response-leg denies
        opa_cm = _make_opa_client_mock(
            allow=False,
            reason="response_sensitivity_exceeds_caller_ceiling",
        )
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            "response_inspection_pipeline": mock_pipeline,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request,
                    path=f"/agents/{target_id}/query",
                    state=state,
                )

        assert response.status_code == 403
        body = response.body
        import json
        body_data = json.loads(body)
        assert body_data["error"] == "AGENT_RESPONSE_BLOCKED"
        assert body_data["reason"] == "response_sensitivity_exceeds_caller_ceiling"

        # Audit event must have been written
        from yashigani.audit.schema import AgentResponseBlockedByOpaEvent
        written_events = [
            call.args[0] for call in audit_writer.write.call_args_list
        ]
        blocked_events = [
            e for e in written_events
            if isinstance(e, AgentResponseBlockedByOpaEvent)
        ]
        assert len(blocked_events) == 1
        ev = blocked_events[0]
        assert ev.caller_agent_id == caller_id
        assert ev.target_agent_id == target_id
        assert ev.response_sensitivity == "CONFIDENTIAL"
        assert ev.deny_reason == "response_sensitivity_exceeds_caller_ceiling"

    @pytest.mark.asyncio
    async def test_scenario_b_public_response_allowed_for_low_clearance_caller(self):
        """
        Scenario B: low-clearance caller (PUBLIC ceiling) calls target agent that
        returns PUBLIC content → OPA allows → HTTP 200, no block event written.
        """
        from yashigani.gateway.agent_router import route_agent_call

        caller_id = "agent-low-clearance"
        target_id = "agent-weather-service"

        registry = _make_registry(
            caller_agent_id=caller_id,
            target_agent_id=target_id,
            caller_ceiling="PUBLIC",
        )
        request = _make_request(caller_id, target_id, request_id="req-integ-002")
        config = _make_config()
        audit_writer = _make_audit_writer()

        upstream_body = "The weather today is sunny and 22°C."
        upstream_resp = _make_upstream_response("text/plain", upstream_body)

        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionResult
        mock_pipeline = MagicMock(spec=ResponseInspectionPipeline)
        mock_pipeline.inspect.return_value = ResponseInspectionResult(
            request_id="req-integ-002",
            verdict="CLEAN",
            confidence=0.99,
            skipped=False,
            skip_reason=None,
            audit_fields={},
            response_sensitivity="PUBLIC",
        )

        # OPA: request-leg allows, response-leg allows
        opa_cm = _make_opa_client_mock(allow=True, reason="ok")
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            "response_inspection_pipeline": mock_pipeline,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request,
                    path=f"/agents/{target_id}/query",
                    state=state,
                )

        assert response.status_code == 200

        # No AGENT_RESPONSE_BLOCKED_BY_OPA event should have been written
        from yashigani.audit.schema import AgentResponseBlockedByOpaEvent
        written_events = [call.args[0] for call in audit_writer.write.call_args_list]
        blocked_events = [e for e in written_events if isinstance(e, AgentResponseBlockedByOpaEvent)]
        assert len(blocked_events) == 0

    @pytest.mark.asyncio
    async def test_scenario_a_without_pipeline_opa_still_checked(self):
        """
        Without inspection pipeline, response_sensitivity defaults to PUBLIC.
        OPA check still runs; PUBLIC vs PUBLIC ceiling → allow.
        """
        from yashigani.gateway.agent_router import route_agent_call

        caller_id = "agent-no-pipeline"
        target_id = "agent-target"

        registry = _make_registry(
            caller_agent_id=caller_id,
            target_agent_id=target_id,
            caller_ceiling="PUBLIC",
        )
        request = _make_request(caller_id, target_id, request_id="req-integ-003")
        config = _make_config()
        audit_writer = _make_audit_writer()

        upstream_resp = _make_upstream_response("text/plain", "Hello world.")

        opa_cm = _make_opa_client_mock(allow=True, reason="ok")
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            # No response_inspection_pipeline — defaults to PUBLIC sensitivity
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request,
                    path=f"/agents/{target_id}/query",
                    state=state,
                )

        # Should be allowed (PUBLIC ≤ PUBLIC ceiling)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_opa_response_check_fail_closed_on_opa_error(self):
        """
        When OPA is unreachable for the response-leg check, agent_router
        returns 403 (fail-closed) — not 200.
        """
        import httpx
        from yashigani.gateway.agent_router import route_agent_call

        caller_id = "agent-caller"
        target_id = "agent-target"

        registry = _make_registry(
            caller_agent_id=caller_id,
            target_agent_id=target_id,
            caller_ceiling="RESTRICTED",
        )
        request = _make_request(caller_id, target_id, request_id="req-integ-004")
        config = _make_config()
        audit_writer = _make_audit_writer()

        upstream_resp = _make_upstream_response("text/plain", "sensitive data")

        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionResult
        mock_pipeline = MagicMock(spec=ResponseInspectionPipeline)
        mock_pipeline.inspect.return_value = ResponseInspectionResult(
            request_id="req-integ-004",
            verdict="CLEAN",
            confidence=0.99,
            skipped=False,
            skip_reason=None,
            audit_fields={},
            response_sensitivity="RESTRICTED",
        )

        call_count = 0

        async def _failing_post(url, json=None, headers=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if "agent_call_allowed" in url:
                # Allow the request-leg check
                resp = MagicMock()
                resp.raise_for_status = MagicMock()
                resp.json = MagicMock(return_value={"result": True})
                return resp
            # Fail the response-leg check
            raise httpx.TimeoutException("OPA timed out")

        mock_client = AsyncMock()
        mock_client.post = _failing_post
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            "response_inspection_pipeline": mock_pipeline,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request,
                    path=f"/agents/{target_id}/query",
                    state=state,
                )

        # Fail-closed: OPA unreachable → 403
        assert response.status_code == 403
        import json
        body_data = json.loads(response.body)
        assert body_data["reason"] == "opa_unreachable"
