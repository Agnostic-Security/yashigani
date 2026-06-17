"""Tests for optimization module: sensitivity classifier and complexity scorer."""
from __future__ import annotations

import pytest

from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
)
from yashigani.optimization.complexity_scorer import (
    ComplexityScorer,
    ComplexityLevel,
)


# ── Sensitivity Classifier ───────────────────────────────────────────────


@pytest.fixture
def classifier():
    return SensitivityClassifier(enable_sklearn=False, enable_ollama=False)


class TestSensitivityClassifier:
    def test_public_text(self, classifier):
        result = classifier.classify("What is the weather today?")
        assert result.level == SensitivityLevel.PUBLIC
        assert len(result.triggers) == 0

    def test_detects_ssn(self, classifier):
        result = classifier.classify("My SSN is 123-45-6789")
        assert result.level == SensitivityLevel.CONFIDENTIAL
        assert any("SSN" in t for t in result.triggers)

    def test_detects_credit_card(self, classifier):
        result = classifier.classify("Card number: 4111 1111 1111 1111")
        assert result.level == SensitivityLevel.RESTRICTED
        assert any("card" in t.lower() for t in result.triggers)

    def test_detects_email(self, classifier):
        result = classifier.classify("Contact alice@company.com for details")
        assert result.level == SensitivityLevel.INTERNAL
        assert any("Email" in t for t in result.triggers)

    def test_detects_api_key(self, classifier):
        result = classifier.classify("Use key sk-ant-abc123def456ghi789jkl012mno345")
        assert result.level == SensitivityLevel.RESTRICTED
        assert any("API key" in t for t in result.triggers)

    def test_detects_classification_marker(self, classifier):
        result = classifier.classify("CONFIDENTIAL: Q3 revenue projections")
        assert result.level == SensitivityLevel.RESTRICTED

    def test_highest_level_wins(self, classifier):
        # Contains both email (INTERNAL) and SSN (CONFIDENTIAL)
        result = classifier.classify("alice@co.com SSN 123-45-6789")
        assert result.level == SensitivityLevel.CONFIDENTIAL

    def test_multiple_triggers(self, classifier):
        result = classifier.classify("SSN 123-45-6789 card 4111111111111111")
        assert len(result.triggers) >= 2

    def test_add_custom_pattern(self, classifier):
        classifier.add_pattern(r"\bPROJECT-X\b", SensitivityLevel.RESTRICTED, "Internal project name")
        result = classifier.classify("This relates to PROJECT-X deliverables")
        assert result.level == SensitivityLevel.RESTRICTED

    def test_reload_patterns(self, classifier):
        classifier.reload_patterns([
            (r"\bFOO\b", SensitivityLevel.CONFIDENTIAL, "Custom"),
        ])
        # Old patterns gone
        result = classifier.classify("123-45-6789")
        assert result.level == SensitivityLevel.PUBLIC
        # New pattern works
        result = classifier.classify("FOO is here")
        assert result.level == SensitivityLevel.CONFIDENTIAL

    def test_layer_results_present(self, classifier):
        result = classifier.classify("Hello world")
        assert "regex" in result.layer_results


# ── Complexity Scorer ────────────────────────────────────────────────────


@pytest.fixture
def scorer():
    return ComplexityScorer(token_threshold=2000)


class TestComplexityScorer:
    def test_short_simple_text_is_low(self, scorer):
        result = scorer.score("What is 2+2?", token_count=5)
        assert result.level == ComplexityLevel.LOW

    def test_long_text_is_high(self, scorer):
        result = scorer.score("x " * 5000, token_count=5000)
        assert result.level == ComplexityLevel.HIGH

    def test_code_blocks_increase_complexity(self, scorer):
        text = "Review this code:\n```python\ndef foo():\n    pass\n```\n```python\ndef bar():\n    pass\n```"
        result = scorer.score(text, token_count=50)
        assert result.heuristic_score > 0
        assert any("code_blocks" in r for r in result.reasons)

    def test_math_content_detected(self, scorer):
        text = "Solve this equation: $$x^2 + 2x + 1 = 0$$ and prove the theorem."
        result = scorer.score(text, token_count=20)
        assert any("math" in r for r in result.reasons)

    def test_medium_complexity(self, scorer):
        result = scorer.score("A moderately long question about something", token_count=1200)
        assert result.level == ComplexityLevel.MEDIUM

    def test_token_count_estimated_when_none(self, scorer):
        result = scorer.score("x" * 400)  # ~100 tokens
        assert result.token_count == 100

    def test_threshold_update(self, scorer):
        scorer.update_threshold(500)
        result = scorer.score("x" * 2400, token_count=600)
        assert result.level == ComplexityLevel.HIGH

    def test_heuristic_threshold_bump(self):
        scorer = ComplexityScorer(token_threshold=2000, heuristic_threshold=0.3)
        text = "```python\nprint('hello')\n```\n```js\nconsole.log('hi')\n```\n$$integral$$"
        result = scorer.score(text, token_count=100)
        # Should be bumped to HIGH by heuristics despite low token count
        assert result.level == ComplexityLevel.HIGH
