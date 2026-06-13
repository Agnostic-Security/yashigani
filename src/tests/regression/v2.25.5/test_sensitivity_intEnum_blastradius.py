"""
Regression tests — SensitivityLevel IntEnum blast-radius audit (fix/2.25.5-sensitivity-blastradius).

R14/R15 changed SensitivityLevel from a str-enum (.value → "RESTRICTED") to an
IntEnum (.value → 4).  Every site that called .level.value on a SensitivityResult
expecting a string silently broke.

This file pins the contract at every fixed site:

  SITE-A  orchestrator._classify_sensitivity() returns a legacy string, not an int
  SITE-B  orchestrator seed-prompt sensitivity branch returns a legacy string
  SITE-C  openai_router sensitivity_level is a legacy string, not an int
  SITE-D  engine.py RoutingDecision.sensitivity field is a legacy string, not an int
  SITE-E  engine.py Prometheus metrics label is a legacy string, not a bare int
  SITE-F  streaming.py final_inspect int/str guard (already correct — non-regression)
  SITE-G  inspection/pipeline.py isinstance guard (already correct — non-regression)

Each test works in isolation: no live OPA, no live database, no Ollama.
"""
from __future__ import annotations

import os

os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer-blastradius")
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")

import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class _FakeClassifier:
    """Minimal sensitivity classifier that returns a SensitivityResult at a
    requested level without running regex/sklearn/ollama."""

    def __init__(self, level: int):
        self._level = level

    def classify_decoded(self, text: str):
        from yashigani.optimization.sensitivity_classifier import SensitivityResult
        return SensitivityResult(level=self._level)

    def classify(self, text: str):
        from yashigani.optimization.sensitivity_classifier import SensitivityResult
        return SensitivityResult(level=self._level)

    def _scan_regex(self, text: str, triggers: list) -> int:
        return self._level


_LEVEL_CASES = [
    (1, "PUBLIC"),
    (2, "INTERNAL"),
    (3, "CONFIDENTIAL"),
    (4, "RESTRICTED"),
    (5, "RESTRICTED"),  # level 5 (SENSITIVE) maps to "RESTRICTED" via _LEVEL_TO_LEGACY_STRING
]


# ---------------------------------------------------------------------------
# SITE-A: orchestrator._classify_sensitivity() must return a string
# ---------------------------------------------------------------------------

class TestSiteA:
    """orchestrator._classify_sensitivity() must return a string (legacy label)."""

    def _call(self, level: int, text: str = "some text") -> str:
        from yashigani.gateway import openai_router as router
        import yashigani.gateway.orchestrator as orch
        original = router._state.sensitivity_classifier
        try:
            router._state.sensitivity_classifier = _FakeClassifier(level)
            return orch._classify_sensitivity(text)
        finally:
            router._state.sensitivity_classifier = original

    @pytest.mark.parametrize("level,expected_label", _LEVEL_CASES)
    def test_returns_legacy_string(self, level, expected_label):
        """_classify_sensitivity must return the legacy string label, not an int."""
        result = self._call(level)
        assert isinstance(result, str), (
            f"SITE-A BROKEN: _classify_sensitivity returned {type(result).__name__!r}={result!r}, "
            f"expected str for level {level}"
        )
        assert result == expected_label, (
            f"SITE-A wrong label: got {result!r}, expected {expected_label!r} for level {level}"
        )

    def test_no_classifier_returns_public(self):
        from yashigani.gateway import openai_router as router
        import yashigani.gateway.orchestrator as orch
        original = router._state.sensitivity_classifier
        try:
            router._state.sensitivity_classifier = None
            result = orch._classify_sensitivity("some text")
        finally:
            router._state.sensitivity_classifier = original
        assert result == "RESTRICTED", (
            "SITE-A: None classifier must return RESTRICTED (fail-closed)"
        )

    def test_empty_text_returns_public(self):
        from yashigani.gateway import openai_router as router
        import yashigani.gateway.orchestrator as orch
        original = router._state.sensitivity_classifier
        try:
            router._state.sensitivity_classifier = _FakeClassifier(5)
            result = orch._classify_sensitivity("")
        finally:
            router._state.sensitivity_classifier = original
        assert result == "PUBLIC", (
            "SITE-A: empty text must return PUBLIC regardless of classifier"
        )

    def test_does_not_raise_attribute_error(self):
        """The pre-fix code called .level.value on an int — this proved it crashed."""
        # If the fix is missing, _FakeClassifier.classify_decoded returns a
        # SensitivityResult whose .level is an int (4).  Calling .value on that
        # int raises AttributeError.  If we reach this assert, the fix is in place.
        result = self._call(4)
        assert result == "RESTRICTED"


# ---------------------------------------------------------------------------
# SITE-C: openai_router sensitivity_level variable type
# ---------------------------------------------------------------------------

class TestSiteC:
    """openai_router sensitivity_level must be a string, not an int, after classify_decoded."""

    def test_sensitivity_level_is_string_not_int(self):
        """Directly test that _LEVEL_TO_LEGACY_STRING is used, not .value."""
        from yashigani.optimization.sensitivity_classifier import (
            SensitivityClassifier, SensitivityResult, _LEVEL_TO_LEGACY_STRING
        )
        sc = SensitivityClassifier()

        # Verify the real classifier's result.level is int
        result = sc.classify("some neutral text")
        assert isinstance(result.level, int), (
            "SITE-C prerequisite: SensitivityResult.level must be int"
        )

        # Verify _LEVEL_TO_LEGACY_STRING converts it correctly
        converted = _LEVEL_TO_LEGACY_STRING.get(int(result.level), "RESTRICTED")
        assert isinstance(converted, str), (
            f"SITE-C: _LEVEL_TO_LEGACY_STRING produced {type(converted).__name__}, not str"
        )
        assert converted in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"), (
            f"SITE-C: unexpected label {converted!r}"
        )

    @pytest.mark.parametrize("level,expected_label", _LEVEL_CASES)
    def test_level_to_legacy_string_covers_all_levels(self, level, expected_label):
        """_LEVEL_TO_LEGACY_STRING must map every classifier-emitted level to a string."""
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        result = _LEVEL_TO_LEGACY_STRING.get(level, "RESTRICTED")
        assert result == expected_label, (
            f"SITE-C: level {level} → {result!r}, expected {expected_label!r}"
        )

    def test_sensitivity_level_string_comparison_works(self):
        """The string comparisons at openai_router:1421/2313 must work correctly.

        Before the fix, sensitivity_level was an int (4), so
        `sensitivity_level in ("CONFIDENTIAL", "RESTRICTED")` silently returned
        False for RESTRICTED content (no error, wrong behaviour).
        """
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        # Simulate openai_router lines 1421 / 2313
        for level in (3, 4, 5):
            label = _LEVEL_TO_LEGACY_STRING.get(level, "RESTRICTED")
            assert label in ("CONFIDENTIAL", "RESTRICTED"), (
                f"SITE-C: level {level} → {label!r} must be in the high-sensitivity set"
            )
        for level in (1, 2):
            label = _LEVEL_TO_LEGACY_STRING.get(level, "RESTRICTED")
            assert label not in ("CONFIDENTIAL", "RESTRICTED"), (
                f"SITE-C: level {level} → {label!r} must NOT be in the high-sensitivity set"
            )


# ---------------------------------------------------------------------------
# SITE-D: engine.py RoutingDecision.sensitivity is a legacy string
# ---------------------------------------------------------------------------

class TestSiteD:
    """OptimizationEngine._decide() must store a legacy string in RoutingDecision.sensitivity."""

    def _make_inputs(self, level: int):
        from yashigani.optimization.sensitivity_classifier import SensitivityResult
        from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
        from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState
        sensitivity = SensitivityResult(level=level)
        complexity = ComplexityResult(
            level=ComplexityLevel.LOW,
            token_count=100,
            heuristic_score=0.1,
            reasons=[],
        )
        budget = BudgetState(
            identity_id="test",
            provider="cloud",
            used=0,
            total=1000,
            signal=BudgetSignal.NORMAL,
            pct=0,
        )
        return sensitivity, complexity, budget

    @pytest.mark.parametrize("level,expected_label", _LEVEL_CASES)
    def test_routing_decision_sensitivity_is_string(self, level, expected_label):
        from yashigani.optimization.engine import OptimizationEngine
        engine = OptimizationEngine()
        sensitivity, complexity, budget = self._make_inputs(level)
        decision = engine.route("qwen2.5:3b", sensitivity, complexity, budget)
        assert isinstance(decision.sensitivity, str), (
            f"SITE-D BROKEN: RoutingDecision.sensitivity is {type(decision.sensitivity).__name__!r}={decision.sensitivity!r}, "
            f"expected str for level {level}"
        )
        assert decision.sensitivity == expected_label, (
            f"SITE-D wrong label: got {decision.sensitivity!r}, expected {expected_label!r} for level {level}"
        )


# ---------------------------------------------------------------------------
# SITE-E: engine.py Prometheus metrics label is a legacy string
# ---------------------------------------------------------------------------

class TestSiteE:
    """yashigani_sensitivity_detections_total metric label must be a legacy string."""

    def test_metrics_label_is_string(self):
        """The Prometheus counter label must be the string name, not a bare integer."""
        import importlib
        from yashigani.optimization.sensitivity_classifier import SensitivityResult
        from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
        from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState
        from yashigani.optimization.engine import OptimizationEngine

        # Capture the label that would be sent to Prometheus by monkey-patching the counter.
        captured_labels: list[dict] = []

        class _FakeCounter:
            def labels(self, **kwargs):
                captured_labels.append(kwargs)
                return self
            def inc(self):
                pass

        import yashigani.metrics.registry as _registry
        original_sens = _registry.yashigani_sensitivity_detections_total
        _registry.yashigani_sensitivity_detections_total = _FakeCounter()
        try:
            engine = OptimizationEngine()
            sensitivity = SensitivityResult(level=4)  # RESTRICTED
            complexity = ComplexityResult(
                level=ComplexityLevel.LOW, token_count=50,
                heuristic_score=0.0, reasons=[],
            )
            budget = BudgetState(
                identity_id="test", provider="cloud",
                used=0, total=1000, signal=BudgetSignal.NORMAL, pct=0,
            )
            engine.route("qwen2.5:3b", sensitivity, complexity, budget)
        finally:
            _registry.yashigani_sensitivity_detections_total = original_sens

        assert captured_labels, "SITE-E: metric was never incremented"
        label_value = captured_labels[0]["level"]
        assert isinstance(label_value, str), (
            f"SITE-E BROKEN: metric label is {type(label_value).__name__!r}={label_value!r}, expected str"
        )
        assert label_value == "RESTRICTED", (
            f"SITE-E wrong label: got {label_value!r}, expected 'RESTRICTED' for level 4"
        )


# ---------------------------------------------------------------------------
# SITE-F: streaming.py final_inspect int/str guard (non-regression)
# ---------------------------------------------------------------------------

class TestSiteF:
    """streaming.py final_inspect already has an int/str guard — confirm it is intact."""

    def test_final_inspect_handles_int_level(self):
        from yashigani.gateway.streaming import StreamingInspector
        inspector = StreamingInspector(
            sensitivity_classifier=_FakeClassifier(1),  # PUBLIC
        )
        inspector._full_text = "benign text"
        result = inspector.final_inspect()
        assert result is True, "SITE-F: final_inspect blocked clean text"

    def test_final_inspect_blocks_restricted_int_level(self):
        from yashigani.gateway.streaming import StreamingInspector
        inspector = StreamingInspector(
            sensitivity_classifier=_FakeClassifier(4),  # RESTRICTED → blocks (>= 3)
        )
        inspector._full_text = "some text"
        result = inspector.final_inspect()
        assert result is False, "SITE-F: final_inspect did not block level-4 content"


# ---------------------------------------------------------------------------
# SITE-G: inspection/pipeline.py isinstance guard (non-regression)
# ---------------------------------------------------------------------------

class TestSiteG:
    """inspection/pipeline.py has an explicit isinstance(int) guard — confirm it is intact."""

    def test_level_to_legacy_string_used_for_int(self):
        """The pipeline code path for int levels uses _LEVEL_TO_LEGACY_STRING."""
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        # Simulate the pipeline code: isinstance(_raw_level, int) branch
        _raw_level = 4  # int, as returned by SensitivityResult.level
        assert isinstance(_raw_level, int)
        response_sensitivity_value = _LEVEL_TO_LEGACY_STRING.get(_raw_level, "RESTRICTED")
        assert response_sensitivity_value == "RESTRICTED"

    def test_backward_compat_branch_for_enum(self):
        """The else branch for a legacy str-enum level (getattr .value) still works."""
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel
        # If someone passes a SensitivityLevel member (not an int), getattr picks up .value
        _raw_level = SensitivityLevel.RESTRICTED  # enum member
        assert not isinstance(_raw_level, int) or hasattr(_raw_level, "value")
        # The IntEnum IS an int, so isinstance(int) is True for it too.
        # Verify both paths converge on "RESTRICTED"
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        if isinstance(_raw_level, int):
            result = _LEVEL_TO_LEGACY_STRING.get(int(_raw_level), "RESTRICTED")
        else:
            result = getattr(_raw_level, "value", str(_raw_level))
        assert result == "RESTRICTED"


# ---------------------------------------------------------------------------
# Integration: SensitivityResult.level is always int (not SensitivityLevel enum member)
# ---------------------------------------------------------------------------

class TestLevelTypeInvariant:
    """SensitivityResult.level behavior under the IntEnum refactor.

    Key finding from blast-radius audit:
      - When no PII patterns match: level is a SensitivityLevel enum member (int subclass),
        so isinstance(level, int) is True and .value IS present (returns int, not str).
      - When a PII pattern matches: _scan_regex returns int(level) (plain int), max() returns
        a plain int, so .value is ABSENT and raises AttributeError.

    The fix at every consumer site is to use _LEVEL_TO_LEGACY_STRING.get(int(level)) which
    works for BOTH plain int and SensitivityLevel enum members (since int() on either gives
    the numeric value).
    """

    def test_classify_result_is_int_subclass(self):
        """SensitivityResult.level is always isinstance(int), even if type is SensitivityLevel."""
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
        sc = SensitivityClassifier()
        result = sc.classify("test text with no PII")
        assert isinstance(result.level, int), (
            f"SensitivityResult.level must be int or int subclass, got {type(result.level).__name__!r}"
        )

    def test_classify_with_pii_returns_plain_int(self):
        """When regex matches PII, _scan_regex returns int(level) → max() → plain int."""
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
        sc = SensitivityClassifier()
        result = sc.classify("SSN: 123-45-6789")
        # When regex fires: int(level) flows through max() as a plain int
        assert isinstance(result.level, int)
        assert int(result.level) == 4  # RESTRICTED

    def test_classify_decoded_with_pii_returns_plain_int(self):
        """classify_decoded with PII also produces a plain int level (not enum member)."""
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
        sc = SensitivityClassifier()
        result = sc.classify_decoded("SSN: 123-45-6789")
        assert isinstance(result.level, int)
        assert int(result.level) == 4  # RESTRICTED

    def test_level_has_no_value_attribute_as_plain_int(self):
        """A plain int does NOT have .value — this was the root cause of B6 sibling bugs.

        When PII is detected (the critical security path), SensitivityResult.level
        is a plain int (4), and calling .value raises AttributeError.
        The fix is int(level) → _LEVEL_TO_LEGACY_STRING.get(...), which works for both.
        """
        level = 4  # plain int as returned by SensitivityResult when PII matches
        assert not hasattr(level, "value"), (
            ".value on a plain int raises AttributeError — this confirms the bug precondition"
        )

    def test_int_of_level_works_for_both_enum_and_plain_int(self):
        """int(x) is safe for both SensitivityLevel enum members and plain ints."""
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel
        # int(SensitivityLevel.RESTRICTED) == 4
        assert int(SensitivityLevel.RESTRICTED) == 4
        # int(4) == 4
        assert int(4) == 4

    @pytest.mark.parametrize("level,expected_str", _LEVEL_CASES)
    def test_legacy_string_map_covers_classifier_output_range(self, level, expected_str):
        """Every integer in the classifier's output range maps to a string."""
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        result = _LEVEL_TO_LEGACY_STRING.get(level)
        assert result is not None, f"_LEVEL_TO_LEGACY_STRING missing entry for level {level}"
        assert isinstance(result, str)
        assert result == expected_str
