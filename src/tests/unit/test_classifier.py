"""
Tests for yashigani.inspection.classifier.

Covers:
  - Label constants are correct strings
  - Default model name is qwen2.5:3b (IC-NEW-2 regression)
  - _parse_response happy path: CLEAN, CREDENTIAL_EXFIL, PROMPT_INJECTION_ONLY
  - _parse_response handles surrounding text / extra whitespace
  - _parse_response on invalid label → CLASSIFIER_ERROR (fail-closed, 5.0 A1)
  - _parse_response on empty string → CLASSIFIER_ERROR
  - _parse_response on valid JSON but out-of-range confidence → clamped
  - _parse_response validates span format
  - classify() error path returns CLASSIFIER_ERROR without raising
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from yashigani.inspection.classifier import (
    LABEL_CLEAN,
    LABEL_CLASSIFIER_ERROR,
    LABEL_CREDENTIAL_EXFIL,
    LABEL_PROMPT_INJECTION_ONLY,
    ClassifierResult,
    PromptInjectionClassifier,
)


# ─────────────────────────────────────────────────────────────────────────────
# Label constants
# ─────────────────────────────────────────────────────────────────────────────

class TestLabelConstants:
    def test_clean_label(self):
        assert LABEL_CLEAN == "CLEAN"

    def test_credential_exfil_label(self):
        assert LABEL_CREDENTIAL_EXFIL == "CREDENTIAL_EXFIL"

    def test_injection_only_label(self):
        assert LABEL_PROMPT_INJECTION_ONLY == "PROMPT_INJECTION_ONLY"

    def test_no_overlapping_labels(self):
        labels = {LABEL_CLEAN, LABEL_CREDENTIAL_EXFIL, LABEL_PROMPT_INJECTION_ONLY}
        assert len(labels) == 3


# ─────────────────────────────────────────────────────────────────────────────
# Default model name regression (IC-NEW-2)
# ─────────────────────────────────────────────────────────────────────────────

class TestDefaultModel:
    def test_default_model_is_qwen25_3b(self):
        """IC-NEW-2 regression: default model must match docs (qwen2.5:3b not qwen3.5:4b)."""
        clf = PromptInjectionClassifier()
        assert clf._model == "qwen2.5:3b"


# ─────────────────────────────────────────────────────────────────────────────
# _parse_response
# ─────────────────────────────────────────────────────────────────────────────

class TestParseResponse:
    def setup_method(self):
        self.clf = PromptInjectionClassifier()

    def _parse(self, data: dict, extra_prefix="", extra_suffix="") -> ClassifierResult:
        raw = extra_prefix + json.dumps(data) + extra_suffix
        return self.clf._parse_response(raw)

    def test_clean_response(self):
        result = self._parse({
            "label": "CLEAN",
            "confidence": 0.97,
            "exfil_indicators": False,
            "detected_payload_spans": [],
        })
        assert result.label == LABEL_CLEAN
        assert result.confidence == pytest.approx(0.97)
        assert result.exfil_indicators is False
        assert result.detected_payload_spans == []

    def test_injection_only_response(self):
        result = self._parse({
            "label": "PROMPT_INJECTION_ONLY",
            "confidence": 0.93,
            "exfil_indicators": False,
            "detected_payload_spans": [{"start": 10, "end": 40}],
        })
        assert result.label == LABEL_PROMPT_INJECTION_ONLY
        assert result.confidence == pytest.approx(0.93)
        assert result.exfil_indicators is False
        assert result.detected_payload_spans == [{"start": 10, "end": 40}]

    def test_credential_exfil_response(self):
        result = self._parse({
            "label": "CREDENTIAL_EXFIL",
            "confidence": 0.99,
            "exfil_indicators": True,
            "detected_payload_spans": [{"start": 5, "end": 60}],
        })
        assert result.label == LABEL_CREDENTIAL_EXFIL
        assert result.confidence == pytest.approx(0.99)
        assert result.exfil_indicators is True
        assert result.detected_payload_spans == [{"start": 5, "end": 60}]

    def test_surrounding_text_extracted(self):
        """Model may produce text before/after JSON — should still parse correctly."""
        inner = json.dumps({
            "label": "CLEAN",
            "confidence": 0.8,
            "exfil_indicators": False,
            "detected_payload_spans": [],
        })
        raw = f"Here is my analysis:\n{inner}\nThank you."
        result = self.clf._parse_response(raw)
        assert result.label == LABEL_CLEAN

    def test_invalid_label_fails_closed(self):
        # 5.0 A1: schema deviation is a classifier failure, never CLEAN —
        # a jailbroken model must not approve content by emitting garbage.
        raw = json.dumps({
            "label": "JAILBREAK",
            "confidence": 0.99,
            "exfil_indicators": True,
            "detected_payload_spans": [],
        })
        result = self.clf._parse_response(raw)
        assert result.label == LABEL_CLASSIFIER_ERROR
        assert result.confidence == pytest.approx(1.0)

    def test_empty_string_fails_closed(self):
        result = self.clf._parse_response("")
        assert result.label == LABEL_CLASSIFIER_ERROR
        assert result.confidence == pytest.approx(1.0)

    def test_confidence_clamped_above_one(self):
        result = self._parse({
            "label": "CLEAN",
            "confidence": 1.5,
            "exfil_indicators": False,
            "detected_payload_spans": [],
        })
        assert result.confidence == pytest.approx(1.0)

    def test_confidence_clamped_below_zero(self):
        result = self._parse({
            "label": "CLEAN",
            "confidence": -0.5,
            "exfil_indicators": False,
            "detected_payload_spans": [],
        })
        assert result.confidence == pytest.approx(0.0)

    def test_invalid_spans_ignored(self):
        result = self._parse({
            "label": "CLEAN",
            "confidence": 0.9,
            "exfil_indicators": False,
            "detected_payload_spans": ["not_a_dict", None, {"only_start": 5}],
        })
        assert result.detected_payload_spans == []

    def test_valid_span_kept(self):
        result = self._parse({
            "label": "PROMPT_INJECTION_ONLY",
            "confidence": 0.9,
            "exfil_indicators": False,
            "detected_payload_spans": [{"start": 5, "end": 20}, {"start": 100, "end": 200}],
        })
        assert len(result.detected_payload_spans) == 2

    def test_span_values_are_ints(self):
        result = self._parse({
            "label": "PROMPT_INJECTION_ONLY",
            "confidence": 0.9,
            "exfil_indicators": False,
            "detected_payload_spans": [{"start": "10", "end": "20"}],
        })
        if result.detected_payload_spans:
            span = result.detected_payload_spans[0]
            assert isinstance(span["start"], int)
            assert isinstance(span["end"], int)

    def test_missing_confidence_defaults_to_zero(self):
        result = self._parse({
            "label": "CLEAN",
            "exfil_indicators": False,
            "detected_payload_spans": [],
        })
        assert result.confidence == pytest.approx(0.0)

    def test_raw_response_stored(self):
        raw = json.dumps({
            "label": "CLEAN",
            "confidence": 0.5,
            "exfil_indicators": False,
            "detected_payload_spans": [],
        })
        result = self.clf._parse_response(raw)
        assert result.raw_response == raw


class TestClassifyErrorPath:
    def test_classify_model_error_fails_closed(self):
        # 5.0 A1 (council P0): model error must NEVER become CLEAN — that was
        # the fail-open the A1×A10 compound Critical exploited.
        clf = PromptInjectionClassifier()
        with patch.object(clf, "_call_model", side_effect=RuntimeError("model unavailable")):
            result = clf.classify("some content")
        assert result.label == LABEL_CLASSIFIER_ERROR
        assert result.confidence == pytest.approx(1.0)
        assert result.exfil_indicators is False
        assert result.raw_response == "RuntimeError"
