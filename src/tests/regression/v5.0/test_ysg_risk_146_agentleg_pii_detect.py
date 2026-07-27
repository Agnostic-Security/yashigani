"""
YSG-RISK-146 (Tier-0 SECURITY): agent-to-agent response leg previously
hardcoded response_pii_detected=False, so PII was never detected on the
/agents/* response leg and OPA could never gate on it there.

Regression coverage:
  1. agent_router.route_agent_call — a PII-bearing agent response sets
     response_pii_detected=True, which reaches the OPA input AND the
     AgentResponseBlockedByOpaEvent audit event.
  2. agent_router.route_agent_call — a clean agent response yields
     response_pii_detected=False.
  3. agent_router.route_agent_call — pii_detector raising fails CLOSED
     (treats the response as PII-positive) rather than silently passing.
  4. orchestrator._detect_pii — real-detection helper used by the MCP-egress
     OPA checks (_opa_egress_for_mcp_result / _opa_egress_for_outbound_args),
     which had the same hardcoded pii_detected=False pattern.

This test module re-derives the request/registry/config/upstream-response
fixtures used in test_v241_gap3_sec5_agent_response_opa.py (integration
suite) rather than importing them, since that module does not export a
public fixture surface.

ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3
Last updated: 2026-07-27T00:00:00+00:00
"""
from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock, AsyncMock, patch


# ---------------------------------------------------------------------------
# Shared fixtures (mirrors test_v241_gap3_sec5_agent_response_opa.py)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _noop_client_enforce(monkeypatch):
    """No-op the #16 client-policy enforce gate — see the GAP-3/SEC-5
    integration suite docstring for why this is required in-process."""
    async def _allow(*_a, **_kw):
        return {"allow": True, "deny": [], "obligations": []}
    monkeypatch.setattr(
        "yashigani.gateway.agent_router.evaluate_client_policies", _allow,
        raising=True)


def _make_registry(caller_agent_id, target_agent_id, caller_ceiling="RESTRICTED"):
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


def _make_request(caller_agent_id, target_agent_id, request_id="req-146-001"):
    req = MagicMock()
    req.method = "POST"
    req.state = MagicMock()
    req.state.agent_id = caller_agent_id
    req.state.request_id = request_id
    req.headers = {}
    req.body = AsyncMock(return_value=b'{"messages": [{"role": "user", "content": "hello"}]}')
    return req


def _make_config(opa_url="https://policy:8181"):
    config = MagicMock()
    config.opa_url = opa_url
    return config


def _make_audit_writer():
    writer = MagicMock()
    writer.write = MagicMock()
    return writer


def _make_opa_client_mock(allow=True, reason="ok"):
    """First call (agent_call_allowed) always allows; second call
    (agent_response_decision) returns the configured allow/reason and
    RECORDS the input payload it was sent so tests can assert on it."""
    sent_inputs = []

    async def _post(url, json=None, headers=None, **kwargs):
        if "agent_call_allowed" in url:
            result = {"result": True}
        else:
            sent_inputs.append(json["input"] if json else None)
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
    return cm, sent_inputs


def _make_upstream_response(content_type, body, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body.encode("utf-8")
    resp.text = body
    headers_mock = MagicMock()
    _hdr_data = {"content-type": content_type}
    headers_mock.get = lambda k, default=None: _hdr_data.get(k, default)
    headers_mock.items = lambda: _hdr_data.items()
    resp.headers = headers_mock
    return resp


def _make_httpx_client_with_upstream(upstream_resp):
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=upstream_resp)

    class _FakeCM:
        async def __aenter__(self):
            return mock_client

        async def __aexit__(self, *a):
            return False

    return _FakeCM(), mock_client


def _make_real_pii_detector(mode="LOG"):
    """Build a real PiiDetector (not a mock) so process_decoded exercises the
    actual regex/scan pipeline against a genuine SSN pattern."""
    from yashigani.pii.detector import PiiDetector, PiiMode
    return PiiDetector(mode=PiiMode[mode])


# ---------------------------------------------------------------------------
# 1 + 2 — route_agent_call: real detection reaches OPA input + audit event
# ---------------------------------------------------------------------------

class TestAgentLegPiiDetectionReal:

    @pytest.mark.asyncio
    async def test_pii_bearing_response_sets_true_reaches_opa_and_audit(self):
        """A PII-bearing agent response -> response_pii_detected True in the
        OPA input AND in AgentResponseBlockedByOpaEvent.pii_detected."""
        from yashigani.gateway.agent_router import route_agent_call

        caller_id, target_id = "agent-caller-146", "agent-target-146"
        registry = _make_registry(caller_id, target_id, caller_ceiling="RESTRICTED")
        request = _make_request(caller_id, target_id)
        config = _make_config()
        audit_writer = _make_audit_writer()

        # SSN in the body — matches the real detector's PII patterns.
        upstream_body = "Customer SSN is 123-45-6789."
        upstream_resp = _make_upstream_response("text/plain", upstream_body)

        # OPA denies on PII (mirrors the Rego pii_detected_in_response rule) so
        # we can assert the audit event fired with the real detection result.
        opa_cm, sent_inputs = _make_opa_client_mock(
            allow=False, reason="pii_detected_in_response")
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        pii_detector = _make_real_pii_detector(mode="LOG")

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            "pii_detector": pii_detector,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request, path=f"/agents/{target_id}/query", state=state)

        assert response.status_code == 403

        # OPA received response_pii_detected=True — not the hardcoded False.
        assert len(sent_inputs) == 1
        assert sent_inputs[0]["response_pii_detected"] is True

        from yashigani.audit.schema import AgentResponseBlockedByOpaEvent
        blocked = [
            c.args[0] for c in audit_writer.write.call_args_list
            if isinstance(c.args[0], AgentResponseBlockedByOpaEvent)
        ]
        assert len(blocked) == 1
        assert blocked[0].pii_detected is True

    @pytest.mark.asyncio
    async def test_clean_response_sets_false(self):
        """A clean agent response (no PII) -> response_pii_detected False,
        OPA input reflects False, response is allowed through."""
        from yashigani.gateway.agent_router import route_agent_call

        caller_id, target_id = "agent-caller-146b", "agent-target-146b"
        registry = _make_registry(caller_id, target_id, caller_ceiling="RESTRICTED")
        request = _make_request(caller_id, target_id, request_id="req-146-002")
        config = _make_config()
        audit_writer = _make_audit_writer()

        upstream_body = "The weather today is sunny and 22C."
        upstream_resp = _make_upstream_response("text/plain", upstream_body)

        opa_cm, sent_inputs = _make_opa_client_mock(allow=True, reason="ok")
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        pii_detector = _make_real_pii_detector(mode="LOG")

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            "pii_detector": pii_detector,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request, path=f"/agents/{target_id}/query", state=state)

        assert response.status_code == 200
        assert len(sent_inputs) == 1
        assert sent_inputs[0]["response_pii_detected"] is False

    @pytest.mark.asyncio
    async def test_no_pii_detector_configured_defaults_false(self):
        """When no pii_detector is wired into state (opt-in feature disabled),
        response_pii_detected stays False — no regression vs. pre-fix
        behaviour for deployments that never enabled PII detection."""
        from yashigani.gateway.agent_router import route_agent_call

        caller_id, target_id = "agent-caller-146c", "agent-target-146c"
        registry = _make_registry(caller_id, target_id, caller_ceiling="RESTRICTED")
        request = _make_request(caller_id, target_id, request_id="req-146-003")
        config = _make_config()
        audit_writer = _make_audit_writer()

        upstream_resp = _make_upstream_response("text/plain", "SSN 123-45-6789")
        opa_cm, sent_inputs = _make_opa_client_mock(allow=True, reason="ok")
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            # No pii_detector key at all.
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request, path=f"/agents/{target_id}/query", state=state)

        assert response.status_code == 200
        assert sent_inputs[0]["response_pii_detected"] is False

    @pytest.mark.asyncio
    async def test_detector_exception_fails_closed_to_pii_positive(self):
        """A raising pii_detector must fail CLOSED (treated as PII-positive),
        not silently fall back to False."""
        from yashigani.gateway.agent_router import route_agent_call

        caller_id, target_id = "agent-caller-146d", "agent-target-146d"
        registry = _make_registry(caller_id, target_id, caller_ceiling="RESTRICTED")
        request = _make_request(caller_id, target_id, request_id="req-146-004")
        config = _make_config()
        audit_writer = _make_audit_writer()

        upstream_resp = _make_upstream_response("text/plain", "irrelevant text")
        # Response-leg OPA denies on PII, proving the fail-closed True reached it.
        opa_cm, sent_inputs = _make_opa_client_mock(
            allow=False, reason="pii_detected_in_response")
        upstream_cm, _ = _make_httpx_client_with_upstream(upstream_resp)

        broken_detector = MagicMock()
        broken_detector.process_decoded = MagicMock(side_effect=RuntimeError("boom"))

        state = {
            "agent_registry": registry,
            "audit_writer": audit_writer,
            "config": config,
            "pii_detector": broken_detector,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=opa_cm):
            with patch("httpx.AsyncClient", return_value=upstream_cm):
                response = await route_agent_call(
                    request=request, path=f"/agents/{target_id}/query", state=state)

        assert response.status_code == 403
        assert sent_inputs[0]["response_pii_detected"] is True


# ---------------------------------------------------------------------------
# 4 — orchestrator._detect_pii: helper feeding the MCP-egress OPA checks
# ---------------------------------------------------------------------------

class TestOrchestratorDetectPii:

    def _reset_state(self, monkeypatch, detector):
        from yashigani.gateway import openai_router as _mod
        monkeypatch.setattr(_mod._state, "pii_detector", detector, raising=False)

    def test_pii_bearing_text_returns_true(self, monkeypatch):
        from yashigani.gateway.orchestrator import _detect_pii
        detector = _make_real_pii_detector(mode="LOG")
        self._reset_state(monkeypatch, detector)
        assert _detect_pii("Customer SSN is 123-45-6789.") is True

    def test_clean_text_returns_false(self, monkeypatch):
        from yashigani.gateway.orchestrator import _detect_pii
        detector = _make_real_pii_detector(mode="LOG")
        self._reset_state(monkeypatch, detector)
        assert _detect_pii("The weather today is sunny.") is False

    def test_no_detector_configured_returns_false(self, monkeypatch):
        from yashigani.gateway.orchestrator import _detect_pii
        self._reset_state(monkeypatch, None)
        assert _detect_pii("Customer SSN is 123-45-6789.") is False

    def test_detector_exception_fails_closed_true(self, monkeypatch):
        from yashigani.gateway.orchestrator import _detect_pii
        broken = MagicMock()
        broken.process_decoded = MagicMock(side_effect=RuntimeError("boom"))
        self._reset_state(monkeypatch, broken)
        assert _detect_pii("irrelevant text") is True

    def test_empty_text_returns_false_without_calling_detector(self, monkeypatch):
        from yashigani.gateway.orchestrator import _detect_pii
        detector = MagicMock()
        self._reset_state(monkeypatch, detector)
        assert _detect_pii("") is False
        detector.process_decoded.assert_not_called()


# ---------------------------------------------------------------------------
# 5 — orchestrator: _opa_egress_for_mcp_result / _opa_egress_for_outbound_args
#     now accept and forward a real pii_detected value.
# ---------------------------------------------------------------------------

class TestOrchestratorEgressHelpersForwardPii:

    @pytest.mark.asyncio
    async def test_opa_egress_for_mcp_result_forwards_pii_detected_true(self, monkeypatch):
        from yashigani.gateway import orchestrator as _orch

        captured = {}

        async def _fake_opa_response_check(**kwargs):
            captured.update(kwargs)
            return {"allow": False, "reason": "pii_detected_in_response"}

        monkeypatch.setattr(
            "yashigani.gateway.openai_router._opa_response_check",
            _fake_opa_response_check, raising=True)

        result = await _orch._opa_egress_for_mcp_result(
            identity={"identity_id": "svc-a"}, server="srv", tool="tool",
            response_verdict="CLEAN", response_sensitivity="PUBLIC",
            pii_detected=True,
        )

        assert captured["pii_detected"] is True
        assert result["allow"] is False

    @pytest.mark.asyncio
    async def test_opa_egress_for_outbound_args_forwards_pii_detected_true(self, monkeypatch):
        from yashigani.gateway import orchestrator as _orch

        captured = {}

        async def _fake_opa_response_check(**kwargs):
            captured.update(kwargs)
            return {"allow": False, "reason": "pii_detected_in_response"}

        monkeypatch.setattr(
            "yashigani.gateway.openai_router._opa_response_check",
            _fake_opa_response_check, raising=True)

        result = await _orch._opa_egress_for_outbound_args(
            identity={"identity_id": "svc-a"}, args_sensitivity="CONFIDENTIAL",
            pii_detected=True,
        )

        assert captured["pii_detected"] is True
        assert result["allow"] is False

    @pytest.mark.asyncio
    async def test_opa_egress_helpers_default_pii_detected_false(self, monkeypatch):
        """Backward-compat: callers that omit pii_detected still get False,
        not an error — default parameter, not a required one."""
        from yashigani.gateway import orchestrator as _orch

        captured = {}

        async def _fake_opa_response_check(**kwargs):
            captured.update(kwargs)
            return {"allow": True, "reason": "ok"}

        monkeypatch.setattr(
            "yashigani.gateway.openai_router._opa_response_check",
            _fake_opa_response_check, raising=True)

        await _orch._opa_egress_for_mcp_result(
            identity={"identity_id": "svc-a"}, server="srv", tool="tool",
            response_verdict="CLEAN", response_sensitivity="PUBLIC",
        )
        assert captured["pii_detected"] is False
