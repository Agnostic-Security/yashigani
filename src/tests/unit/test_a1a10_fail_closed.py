"""
5.0 A1×A10 (tier1 council P0) — fail-closed inspection regression tests.

Locks in the council-mandated behaviour:
  A1: classifier error / unparseable verdict → CLASSIFIER_ERROR, disposed as
      DISCARDED with its own audit label (never laundered into CLEAN, never
      confidence-1.0 pass-through).
  A1: registry construction failure → fail_closed_registry blocks everything
      (never the bare fail-open classifier).
  A10: per-identity concurrency cap — over-cap identity sheds ITS OWN
      requests fail-closed; other identities are unaffected.
"""
from __future__ import annotations

import pytest

from yashigani.inspection.classifier import (
    ClassifierResult,
    LABEL_CLASSIFIER_ERROR,
    LABEL_CLEAN,
    PromptInjectionClassifier,
)
from yashigani.inspection.concurrency_guard import IdentityConcurrencyGuard
from yashigani.inspection.pipeline import (
    InspectionPipeline,
    LABEL_COMPUTE_SHED,
    ResponseInspectionPipeline,
    RESPONSE_VERDICT_BLOCKED,
    RESPONSE_VERDICT_CLEAN,
)


class _StubClassifier(PromptInjectionClassifier):
    """Returns a canned result; never touches the network."""

    def __init__(self, result: ClassifierResult) -> None:
        super().__init__(model="stub-model", ollama_base_url="http://stub:0")
        self._result = result

    def classify(self, content: str) -> ClassifierResult:
        return self._result


def _error_result() -> ClassifierResult:
    return ClassifierResult(
        label=LABEL_CLASSIFIER_ERROR,
        confidence=1.0,
        exfil_indicators=False,
        detected_payload_spans=[],
        raw_response="TimeoutError",
    )


def _clean_result() -> ClassifierResult:
    return ClassifierResult(
        label=LABEL_CLEAN,
        confidence=0.97,
        exfil_indicators=False,
        detected_payload_spans=[],
    )


class TestClassifierErrorDisposition:
    def test_classifier_error_discards_and_audits(self):
        events: list[tuple[str, dict]] = []
        pipeline = InspectionPipeline(
            classifier=_StubClassifier(_error_result()),
            on_audit=lambda name, data: events.append((name, data)),
        )
        result = pipeline.process("hello", "sess-1", "agent-1", "user-1")

        assert result.action == "DISCARDED"
        assert result.clean_query is None
        assert result.classification == LABEL_CLASSIFIER_ERROR
        assert result.severity == "HIGH"
        # The audit label distinguishes classifier-error from a genuine verdict
        assert events and events[0][0] == "INSPECTION_CLASSIFIER_ERROR"
        assert events[0][1]["classification"] == LABEL_CLASSIFIER_ERROR
        assert result.user_alert is not None

    def test_clean_still_passes(self):
        pipeline = InspectionPipeline(classifier=_StubClassifier(_clean_result()))
        result = pipeline.process("hello", "sess-1", "agent-1", "user-1")
        assert result.action == "PASS"
        assert result.clean_query == "hello"

    def test_response_pipeline_blocks_on_classifier_error(self):
        pipeline = ResponseInspectionPipeline(classifier=_StubClassifier(_error_result()))
        result = pipeline.inspect(
            response_body="some upstream text",
            content_type="text/plain",
            request_id="req-1",
            session_id="sess-1",
            agent_id="agent-1",
        )
        assert result.verdict == RESPONSE_VERDICT_BLOCKED
        assert result.skipped is False


class TestFailClosedRegistry:
    def test_fail_closed_registry_blocks_everything(self):
        from yashigani.inspection.backend_registry import fail_closed_registry

        registry = fail_closed_registry("redis exploded")
        verdict = registry.classify("anything", request_id="req-1")
        assert verdict.label == "PROMPT_INJECTION_ONLY"
        assert verdict.confidence == pytest.approx(1.0)
        assert verdict.backend == "fail_closed"

    def test_pipeline_with_fail_closed_registry_discards(self):
        from yashigani.inspection.backend_registry import fail_closed_registry

        pipeline = InspectionPipeline(
            classifier=_StubClassifier(_clean_result()),  # must NOT be consulted
            backend_registry=fail_closed_registry("boom"),
        )
        result = pipeline.process("hello", "sess-1", "agent-1", "user-1")
        assert result.action == "DISCARDED"


class TestIdentityConcurrencyGuard:
    def test_cap_is_per_identity(self):
        guard = IdentityConcurrencyGuard(max_per_identity=2)
        assert guard.try_acquire("alice")
        assert guard.try_acquire("alice")
        assert not guard.try_acquire("alice")  # alice at cap
        assert guard.try_acquire("bob")        # bob unaffected
        guard.release("alice")
        assert guard.try_acquire("alice")      # slot freed

    def test_release_drops_zeroed_buckets(self):
        guard = IdentityConcurrencyGuard(max_per_identity=1)
        guard.try_acquire("alice")
        guard.release("alice")
        assert guard.in_flight("alice") == 0

    def test_empty_identity_shares_one_bucket(self):
        guard = IdentityConcurrencyGuard(max_per_identity=1)
        assert guard.try_acquire("")
        assert not guard.try_acquire("")  # no fresh bucket for anonymous

    def test_slot_context_releases_on_exception(self):
        guard = IdentityConcurrencyGuard(max_per_identity=1)
        with pytest.raises(RuntimeError):
            with guard.slot("alice") as acquired:
                assert acquired
                raise RuntimeError("boom")
        assert guard.in_flight("alice") == 0

    def test_min_cap_validated(self):
        with pytest.raises(ValueError):
            IdentityConcurrencyGuard(max_per_identity=0)


class TestComputeShedDisposition:
    def test_request_shed_is_fail_closed_and_scoped(self):
        events: list[tuple[str, dict]] = []
        guard = IdentityConcurrencyGuard(max_per_identity=1)
        pipeline = InspectionPipeline(
            classifier=_StubClassifier(_clean_result()),
            on_audit=lambda name, data: events.append((name, data)),
            concurrency_guard=guard,
        )
        # Saturate user-1's only slot, then process as user-1 → shed
        assert guard.try_acquire("user-1")
        result = pipeline.process("hello", "sess-1", "agent-1", "user-1")
        assert result.action == "DISCARDED"
        assert result.classification == LABEL_COMPUTE_SHED
        assert events and events[0][0] == "CLASSIFIER_COMPUTE_SHED"

        # A different identity still classifies normally (shed is scoped)
        result2 = pipeline.process("hello", "sess-2", "agent-1", "user-2")
        assert result2.action == "PASS"

        # user-1 recovers once its slot frees
        guard.release("user-1")
        result3 = pipeline.process("hello", "sess-3", "agent-1", "user-1")
        assert result3.action == "PASS"

    def test_response_shed_blocks(self):
        guard = IdentityConcurrencyGuard(max_per_identity=1)
        pipeline = ResponseInspectionPipeline(
            classifier=_StubClassifier(_clean_result()),
            concurrency_guard=guard,
        )
        assert guard.try_acquire("agent-1")
        result = pipeline.inspect(
            response_body="text",
            content_type="text/plain",
            request_id="req-1",
            session_id="sess-1",
            agent_id="agent-1",
        )
        assert result.verdict == RESPONSE_VERDICT_BLOCKED

        guard.release("agent-1")
        result2 = pipeline.inspect(
            response_body="text",
            content_type="text/plain",
            request_id="req-2",
            session_id="sess-1",
            agent_id="agent-1",
        )
        assert result2.verdict == RESPONSE_VERDICT_CLEAN
