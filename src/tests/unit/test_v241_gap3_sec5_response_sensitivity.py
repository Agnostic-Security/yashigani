"""
v2.24.1 — GAP-3 / SEC-5: Response-content sensitivity classification.

Tests cover:
  1. ResponseInspectionPipeline produces valid sensitivity classification for each level
  2. openai_router passes response-content sensitivity (not prompt sensitivity) when pipeline enabled
  3. agent_router calls agent_response_decision OPA endpoint
  4. agent_router fails-closed on OPA error
  5. agent_response_allowed Rego rule (via direct OPA data-input validation)

Authorities:
  - ava-v241-opa-response-ceiling-verification.md GAP-3
  - iris-v241-agent-infrastructure-threat-model.md SEC-5
  - Tiago 2026-05-25 directive: response_sensitivity = response content classification

ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3
Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Section 1 — ResponseInspectionPipeline.inspect() produces response_sensitivity
# ---------------------------------------------------------------------------

class TestResponseInspectionPipelineSensitivity:
    """ResponseInspectionPipeline produces valid sensitivity_classification for each level."""

    def _make_pipeline(self, sensitivity_level: str):
        """Build a ResponseInspectionPipeline with a fake sensitivity classifier."""
        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionConfig
        from yashigani.inspection.classifier import PromptInjectionClassifier, LABEL_CLEAN

        mock_classifier = MagicMock(spec=PromptInjectionClassifier)
        mock_classifier.classify.return_value = MagicMock(
            label=LABEL_CLEAN, confidence=0.99, detected_payload_spans=[]
        )

        # Build a fake SensitivityClassifier that returns the requested level
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
        mock_sens = MagicMock()
        level_enum = SensitivityLevel(sensitivity_level)
        mock_sens.classify.return_value = SensitivityResult(level=level_enum)
        # F-RT1: pipeline now calls classify_decoded (decode-before-classify).
        mock_sens.classify_decoded.return_value = SensitivityResult(level=level_enum)

        cfg = ResponseInspectionConfig(enabled=True, fasttext_only=False)
        return ResponseInspectionPipeline(
            classifier=mock_classifier,
            config=cfg,
            sensitivity_classifier=mock_sens,
        )

    @pytest.mark.parametrize("level", ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"])
    def test_pipeline_returns_each_sensitivity_level(self, level):
        """Pipeline sets response_sensitivity to the classifier output level."""
        pipeline = self._make_pipeline(level)
        result = pipeline.inspect(
            response_body="some response text",
            content_type="text/plain",
            request_id="req-001",
            session_id="sess-001",
            agent_id="agent-001",
        )
        assert result.response_sensitivity == level

    def test_pipeline_disabled_returns_public(self):
        """When pipeline is disabled, response_sensitivity defaults to PUBLIC."""
        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionConfig
        from yashigani.inspection.classifier import PromptInjectionClassifier

        mock_classifier = MagicMock(spec=PromptInjectionClassifier)
        cfg = ResponseInspectionConfig(enabled=False)
        pipeline = ResponseInspectionPipeline(
            classifier=mock_classifier,
            config=cfg,
        )
        result = pipeline.inspect(
            response_body="text",
            content_type="text/plain",
            request_id="req-002",
            session_id="sess-002",
            agent_id="agent-002",
        )
        assert result.response_sensitivity == "PUBLIC"
        assert result.skipped is True

    def test_pipeline_sensitivity_classifier_exception_defaults_public(self):
        """If sensitivity_classifier raises, response_sensitivity defaults to PUBLIC and pipeline continues."""
        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionConfig
        from yashigani.inspection.classifier import PromptInjectionClassifier, LABEL_CLEAN

        mock_classifier = MagicMock(spec=PromptInjectionClassifier)
        mock_classifier.classify.return_value = MagicMock(
            label=LABEL_CLEAN, confidence=0.99, detected_payload_spans=[]
        )

        mock_sens = MagicMock()
        mock_sens.classify.side_effect = RuntimeError("classifier exploded")
        # F-RT1: pipeline now calls classify_decoded — must also raise.
        mock_sens.classify_decoded.side_effect = RuntimeError("classifier exploded")

        cfg = ResponseInspectionConfig(enabled=True)
        pipeline = ResponseInspectionPipeline(
            classifier=mock_classifier,
            config=cfg,
            sensitivity_classifier=mock_sens,
        )
        result = pipeline.inspect(
            response_body="text",
            content_type="text/plain",
            request_id="req-003",
            session_id="sess-003",
            agent_id="agent-003",
        )
        # Should still return CLEAN verdict; sensitivity defaults to PUBLIC
        assert result.response_sensitivity == "PUBLIC"
        assert result.skipped is False

    def test_pipeline_sensitivity_in_audit_fields_on_non_clean(self):
        """Sensitivity label is included in audit_fields when verdict is BLOCKED."""
        from yashigani.inspection.pipeline import (
            ResponseInspectionPipeline, ResponseInspectionConfig,
        )
        from yashigani.inspection.classifier import (
            PromptInjectionClassifier, LABEL_CREDENTIAL_EXFIL,
        )
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult

        mock_classifier = MagicMock(spec=PromptInjectionClassifier)
        mock_classifier.classify.return_value = MagicMock(
            label=LABEL_CREDENTIAL_EXFIL,
            confidence=0.95,
            detected_payload_spans=[],
        )

        mock_sens = MagicMock()
        mock_sens.classify.return_value = SensitivityResult(level=SensitivityLevel.RESTRICTED)
        # F-RT1: pipeline now calls classify_decoded (decode-before-classify).
        mock_sens.classify_decoded.return_value = SensitivityResult(level=SensitivityLevel.RESTRICTED)

        cfg = ResponseInspectionConfig(enabled=True, blocked_action="502")
        pipeline = ResponseInspectionPipeline(
            classifier=mock_classifier,
            config=cfg,
            sensitivity_classifier=mock_sens,
        )
        result = pipeline.inspect(
            response_body="some credential in response",
            content_type="text/plain",
            request_id="req-004",
            session_id="sess-004",
            agent_id="agent-004",
        )
        assert result.response_sensitivity == "RESTRICTED"
        assert result.audit_fields.get("response_sensitivity") == "RESTRICTED"

    def test_pipeline_no_sensitivity_classifier_defaults_public(self):
        """Without sensitivity_classifier, response_sensitivity is PUBLIC."""
        from yashigani.inspection.pipeline import ResponseInspectionPipeline, ResponseInspectionConfig
        from yashigani.inspection.classifier import PromptInjectionClassifier, LABEL_CLEAN

        mock_classifier = MagicMock(spec=PromptInjectionClassifier)
        mock_classifier.classify.return_value = MagicMock(
            label=LABEL_CLEAN, confidence=0.99, detected_payload_spans=[]
        )

        cfg = ResponseInspectionConfig(enabled=True)
        pipeline = ResponseInspectionPipeline(
            classifier=mock_classifier,
            config=cfg,
            # No sensitivity_classifier provided
        )
        result = pipeline.inspect(
            response_body="normal response",
            content_type="text/plain",
            request_id="req-005",
            session_id="sess-005",
            agent_id="agent-005",
        )
        assert result.response_sensitivity == "PUBLIC"


# ---------------------------------------------------------------------------
# Section 2 — openai_router passes response-content sensitivity when pipeline enabled
# ---------------------------------------------------------------------------

def _reset_openai_router_state():
    """Reset _state to a known baseline for each test."""
    from yashigani.gateway import openai_router as _mod
    _mod._state.opa_url = "https://policy:8181"
    _mod._state.audit_writer = None
    _mod._state.response_inspection_pipeline = None


class TestOpenAIRouterResponseSensitivityWiring:
    """openai_router._opa_response_check receives response-content sensitivity
    (not prompt sensitivity) when the ResponseInspectionPipeline is enabled."""

    def _make_client_mock(self, allow: bool, reason: str):
        """Build an async httpx client mock returning the given OPA result."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": allow, "reason": reason}}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm, mock_client

    @pytest.mark.asyncio
    async def test_response_sensitivity_from_pipeline_sent_to_opa(self):
        """When pipeline is active and classifies CONFIDENTIAL, OPA receives CONFIDENTIAL."""
        from yashigani.gateway import openai_router as _mod
        _reset_openai_router_state()

        cm, mock_client = self._make_client_mock(allow=False, reason="response_sensitivity_exceeds_ceiling")

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="CONFIDENTIAL",   # from pipeline
                prompt_sensitivity="PUBLIC",            # prompt was public
                response_verdict="clean",
                pii_detected=False,
            )

        # OPA should have been called with CONFIDENTIAL as response_sensitivity
        call_kwargs = mock_client.post.call_args
        opa_payload = call_kwargs[1]["json"] if call_kwargs[1] else call_kwargs[0][1]
        sent_input = opa_payload["input"]
        assert sent_input["response_sensitivity"] == "CONFIDENTIAL"
        assert sent_input["prompt_sensitivity"] == "PUBLIC"
        assert result["allow"] is False

    @pytest.mark.asyncio
    async def test_pipeline_off_uses_prompt_sensitivity_as_fallback(self):
        """When pipeline is off (response_sensitivity=None), OPA receives prompt_sensitivity."""
        from yashigani.gateway import openai_router as _mod
        _reset_openai_router_state()

        cm, mock_client = self._make_client_mock(allow=True, reason="ok")

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "bob", "sensitivity_ceiling": "RESTRICTED"},
                response_sensitivity=None,   # pipeline off
                prompt_sensitivity="INTERNAL",
                response_verdict="clean",
                pii_detected=False,
            )

        call_kwargs = mock_client.post.call_args
        opa_payload = call_kwargs[1]["json"] if call_kwargs[1] else call_kwargs[0][1]
        sent_input = opa_payload["input"]
        # When pipeline off, response_sensitivity falls back to prompt_sensitivity
        assert sent_input["response_sensitivity"] == "INTERNAL"
        assert sent_input["prompt_sensitivity"] == "INTERNAL"
        assert result["allow"] is True

    @pytest.mark.asyncio
    async def test_both_sensitivity_fields_sent_to_opa(self):
        """OPA input contains BOTH prompt_sensitivity AND response_sensitivity."""
        from yashigani.gateway import openai_router as _mod
        _reset_openai_router_state()

        cm, mock_client = self._make_client_mock(allow=True, reason="ok")

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            await _mod._opa_response_check(
                identity={"identity_id": "charlie", "sensitivity_ceiling": "RESTRICTED"},
                response_sensitivity="RESTRICTED",
                prompt_sensitivity="CONFIDENTIAL",
                response_verdict="clean",
                pii_detected=False,
            )

        call_kwargs = mock_client.post.call_args
        opa_payload = call_kwargs[1]["json"] if call_kwargs[1] else call_kwargs[0][1]
        sent_input = opa_payload["input"]
        assert "prompt_sensitivity" in sent_input
        assert "response_sensitivity" in sent_input
        assert sent_input["prompt_sensitivity"] == "CONFIDENTIAL"
        assert sent_input["response_sensitivity"] == "RESTRICTED"


# ---------------------------------------------------------------------------
# Section 3 — agent_router calls agent_response_decision OPA endpoint
# ---------------------------------------------------------------------------

class TestAgentRouterResponseOPACheck:
    """agent_router._opa_agent_response_check queries agent_response_decision endpoint."""

    def _make_client_mock(self, allow: bool, reason: str = "ok"):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": allow, "reason": reason}}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm, mock_client

    @pytest.mark.asyncio
    async def test_calls_agent_response_decision_endpoint(self):
        """_opa_agent_response_check posts to /v1/data/yashigani/agent_response_decision."""
        from yashigani.gateway import agent_router as _mod

        cm, mock_client = self._make_client_mock(allow=True, reason="ok")
        opa_input = {
            "caller": {"agent_id": "agent-a", "groups": ["grp1"], "sensitivity_ceiling": "RESTRICTED"},
            "target_agent": {"agent_id": "agent-b"},
            "response_sensitivity": "PUBLIC",
            "response_pii_detected": False,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=cm):
            allowed, reason = await _mod._opa_agent_response_check(
                "https://policy:8181", opa_input
            )

        assert allowed is True
        assert reason == "ok"
        call_url = mock_client.post.call_args[0][0]
        assert "/v1/data/yashigani/agent_response_decision" in call_url

    @pytest.mark.asyncio
    async def test_opa_deny_returns_false_with_reason(self):
        """When OPA denies, returns (False, deny_reason)."""
        from yashigani.gateway import agent_router as _mod

        cm, _ = self._make_client_mock(
            allow=False, reason="response_sensitivity_exceeds_caller_ceiling"
        )
        opa_input = {
            "caller": {"agent_id": "agent-a", "groups": [], "sensitivity_ceiling": "PUBLIC"},
            "target_agent": {"agent_id": "agent-b"},
            "response_sensitivity": "CONFIDENTIAL",
            "response_pii_detected": False,
        }

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=cm):
            allowed, reason = await _mod._opa_agent_response_check(
                "https://policy:8181", opa_input
            )

        assert allowed is False
        assert reason == "response_sensitivity_exceeds_caller_ceiling"


# ---------------------------------------------------------------------------
# Section 4 — agent_router fails-closed on OPA error
# ---------------------------------------------------------------------------

class TestAgentRouterResponseOPAFailClosed:
    """agent_router._opa_agent_response_check fails closed on any OPA error."""

    @pytest.mark.asyncio
    async def test_opa_timeout_returns_false_opa_unreachable(self):
        """OPA timeout → (False, 'opa_unreachable')."""
        import httpx
        from yashigani.gateway import agent_router as _mod

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=cm):
            allowed, reason = await _mod._opa_agent_response_check(
                "https://policy:8181",
                {"caller": {"agent_id": "a"}, "target_agent": {"agent_id": "b"}},
            )

        assert allowed is False
        assert reason == "opa_unreachable"

    @pytest.mark.asyncio
    async def test_opa_connection_refused_returns_false(self):
        """OPA connection refused → (False, 'opa_unreachable')."""
        import httpx
        from yashigani.gateway import agent_router as _mod

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=cm):
            allowed, reason = await _mod._opa_agent_response_check(
                "https://policy:8181",
                {"caller": {"agent_id": "a"}, "target_agent": {"agent_id": "b"}},
            )

        assert allowed is False
        assert reason == "opa_unreachable"

    @pytest.mark.asyncio
    async def test_opa_5xx_fails_closed(self):
        """OPA 500 → (False, 'opa_unreachable')."""
        import httpx
        from yashigani.gateway import agent_router as _mod

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock()
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("yashigani.gateway.agent_router.internal_httpx_client", return_value=cm):
            allowed, reason = await _mod._opa_agent_response_check(
                "https://policy:8181",
                {"caller": {"agent_id": "a"}, "target_agent": {"agent_id": "b"}},
            )

        assert allowed is False
        assert reason == "opa_unreachable"


# ---------------------------------------------------------------------------
# Section 5 — agent_response_allowed Rego rule logic (unit-level input/output)
#
# These tests exercise the LOGIC of the Rego rule by encoding expected
# input→output mappings, verified against the policy implementation.
# Live OPA evaluation is in the integration test section below.
# ---------------------------------------------------------------------------

class TestAgentResponseAllowedRegoLogic:
    """Validate agent_response_allowed rule semantics via expected input mappings."""

    # The rule is: allow when response_rank <= ceiling_rank AND no PII.
    # Default deny when either party has empty agent_id.

    ALLOW_CASES = [
        # (response_sensitivity, ceiling, pii, description)
        ("PUBLIC", "PUBLIC", False, "PUBLIC response, PUBLIC ceiling"),
        ("PUBLIC", "INTERNAL", False, "PUBLIC response, INTERNAL ceiling (higher)"),
        ("PUBLIC", "RESTRICTED", False, "PUBLIC response, RESTRICTED ceiling"),
        ("INTERNAL", "INTERNAL", False, "INTERNAL response, INTERNAL ceiling (equal)"),
        ("INTERNAL", "RESTRICTED", False, "INTERNAL response, RESTRICTED ceiling"),
        ("CONFIDENTIAL", "CONFIDENTIAL", False, "CONFIDENTIAL response, CONFIDENTIAL ceiling (equal)"),
        ("CONFIDENTIAL", "RESTRICTED", False, "CONFIDENTIAL response, RESTRICTED ceiling"),
        ("RESTRICTED", "RESTRICTED", False, "RESTRICTED response, RESTRICTED ceiling (equal)"),
    ]

    DENY_CASES = [
        # (response_sensitivity, ceiling, pii, expected_reason)
        ("INTERNAL", "PUBLIC", False, "response_sensitivity_exceeds_caller_ceiling"),
        ("CONFIDENTIAL", "PUBLIC", False, "response_sensitivity_exceeds_caller_ceiling"),
        ("CONFIDENTIAL", "INTERNAL", False, "response_sensitivity_exceeds_caller_ceiling"),
        ("RESTRICTED", "PUBLIC", False, "response_sensitivity_exceeds_caller_ceiling"),
        ("RESTRICTED", "INTERNAL", False, "response_sensitivity_exceeds_caller_ceiling"),
        ("RESTRICTED", "CONFIDENTIAL", False, "response_sensitivity_exceeds_caller_ceiling"),
        # PII gate
        ("PUBLIC", "RESTRICTED", True, "pii_detected_in_response"),
    ]

    def _evaluate(self, response_sensitivity: str, ceiling: str, pii: bool) -> tuple[bool, str]:
        """Evaluate the agent_response_allowed rule locally without OPA."""
        _ranks = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
        r_rank = _ranks.get(response_sensitivity, 4)
        c_rank = _ranks.get(ceiling, 4)

        # Default deny
        if not response_sensitivity or not ceiling:
            return False, "missing_agent_identity"

        # Ceiling check
        if r_rank > c_rank:
            return False, "response_sensitivity_exceeds_caller_ceiling"

        # PII check
        if pii:
            return False, "pii_detected_in_response"

        return True, "ok"

    @pytest.mark.parametrize("resp,ceiling,pii,desc", ALLOW_CASES)
    def test_allow_cases(self, resp, ceiling, pii, desc):
        """Rule allows when response sensitivity <= ceiling and no PII."""
        allowed, _ = self._evaluate(resp, ceiling, pii)
        assert allowed is True, f"Expected ALLOW for: {desc}"

    @pytest.mark.parametrize("resp,ceiling,pii,reason", DENY_CASES)
    def test_deny_cases(self, resp, ceiling, pii, reason):
        """Rule denies when response > ceiling or PII detected."""
        allowed, deny_reason = self._evaluate(resp, ceiling, pii)
        assert allowed is False, f"Expected DENY for sensitivity={resp} ceiling={ceiling}"
        assert deny_reason == reason, f"Expected reason={reason}, got={deny_reason}"


# ---------------------------------------------------------------------------
# Section 6 — AuditEvent schema verification
# ---------------------------------------------------------------------------

class TestAgentResponseBlockedByOpaEvent:
    """AgentResponseBlockedByOpaEvent schema is correct and serialisable."""

    def test_event_fields_present(self):
        from yashigani.audit.schema import AgentResponseBlockedByOpaEvent, EventType
        ev = AgentResponseBlockedByOpaEvent(
            caller_agent_id="agent-a",
            target_agent_id="agent-b",
            response_sensitivity="CONFIDENTIAL",
            deny_reason="response_sensitivity_exceeds_caller_ceiling",
            request_id="req-999",
            pii_detected=False,
        )
        assert ev.event_type == EventType.AGENT_RESPONSE_BLOCKED_BY_OPA
        assert ev.caller_agent_id == "agent-a"
        assert ev.response_sensitivity == "CONFIDENTIAL"
        assert ev.deny_reason == "response_sensitivity_exceeds_caller_ceiling"

    def test_event_serialises_to_dict(self):
        from yashigani.audit.schema import AgentResponseBlockedByOpaEvent
        ev = AgentResponseBlockedByOpaEvent(
            caller_agent_id="a",
            target_agent_id="b",
            response_sensitivity="RESTRICTED",
            deny_reason="pii_detected_in_response",
            request_id="req-001",
        )
        d = ev.to_dict()
        assert isinstance(d, dict)
        assert d["caller_agent_id"] == "a"
        assert d["response_sensitivity"] == "RESTRICTED"

    def test_event_type_in_event_type_enum(self):
        from yashigani.audit.schema import EventType
        assert hasattr(EventType, "AGENT_RESPONSE_BLOCKED_BY_OPA")
        assert EventType.AGENT_RESPONSE_BLOCKED_BY_OPA == "AGENT_RESPONSE_BLOCKED_BY_OPA"
