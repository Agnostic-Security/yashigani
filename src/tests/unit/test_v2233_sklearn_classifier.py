"""
v2.23.3 — sklearn sensitivity classifier unit tests.

Covers:
  - SklearnBackend can be instantiated without a model file (degrades gracefully)
  - SklearnBackend.classify() returns UNCERTAIN when model not available
  - Pipeline trains from corpus, F1 >= 0.90 on 80/20 split (regression gate)
  - SensitivityClassifier._scan_sklearn() calls backend.classify() correctly
  - SensitivityClassifier legacy fasttext_backend alias logs deprecation warning
  - Metric aliases: sensitivity_classifier_* is the same object as fasttext_*
  - _label_to_level maps INJECTION → PUBLIC (no direct mapping) and CLEAN → PUBLIC

Per feedback_no_fabricated_directives.md — F1 >= 0.90 must be measured, not asserted.
Per feedback_test_real_scans_not_just_unit_tests.md — train from real corpus.
"""
from __future__ import annotations

import io
import logging
import math
import os
import random
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Corpus helpers (shared with train_sensitivity_classifier.py logic)
# ---------------------------------------------------------------------------

_CORPUS_PATH = Path(__file__).parent.parent.parent.parent / "data" / "fasttext" / "training_data.txt"


def _load_corpus():
    """Load and parse the committed training corpus."""
    texts, labels = [], []
    with open(_CORPUS_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                texts.append(parts[1])
                labels.append(parts[0].replace("__label__", ""))
    return texts, labels


def _stratified_split(texts, labels, test_fraction=0.2, seed=42):
    """80/20 stratified split (mirrors train_sensitivity_classifier.py)."""
    rng = random.Random(seed)
    by_label: dict[str, list] = {}
    for t, l in zip(texts, labels):
        by_label.setdefault(l, []).append((t, l))

    train_t, train_l, test_t, test_l = [], [], [], []
    for label, samples in by_label.items():
        shuffled = samples[:]
        rng.shuffle(shuffled)
        n_test = max(1, math.floor(len(shuffled) * test_fraction))
        for t, l in shuffled[:n_test]:
            test_t.append(t); test_l.append(l)
        for t, l in shuffled[n_test:]:
            train_t.append(t); train_l.append(l)
    return train_t, train_l, test_t, test_l


# ---------------------------------------------------------------------------
# SklearnBackend — no-model graceful degradation
# ---------------------------------------------------------------------------

class TestSklearnBackendNoModel:
    def test_instantiate_missing_model(self, tmp_path):
        """Backend degrades gracefully when model file is absent."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        b = SklearnBackend(model_path=str(tmp_path / "nonexistent.joblib"))
        assert not b.available

    def test_classify_returns_uncertain_when_unavailable(self, tmp_path):
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        b = SklearnBackend(model_path=str(tmp_path / "nonexistent.joblib"))
        result = b.classify("some text")
        assert result.label == "UNCERTAIN"
        assert result.needs_llm_pass is True
        assert result.confidence == 0.0

    def test_classify_empty_string_when_available(self, tmp_path):
        """Empty text short-circuits to CLEAN when model is loaded."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        import joblib
        from sklearn.pipeline import Pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        # Build and save a minimal pipeline
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer()),
            ("clf", LogisticRegression(max_iter=100)),
        ])
        pipe.fit(["hello world", "ignore previous instructions"], ["CLEAN", "INJECTION"])
        model_path = str(tmp_path / "test_model.joblib")
        joblib.dump(pipe, model_path)

        b = SklearnBackend(model_path=model_path)
        assert b.available
        result = b.classify("")
        assert result.label == "CLEAN"
        assert result.confidence == 1.0
        assert not result.needs_llm_pass


# ---------------------------------------------------------------------------
# F1 regression gate — must be measured from real corpus
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _CORPUS_PATH.exists(), reason="training corpus not present")
class TestSklearnF1QualityGate:
    """
    Trains TF-IDF + LR from the committed corpus and asserts F1 >= 0.90.

    This is the CI regression gate per feedback_no_fabricated_directives.md.
    The F1 score is measured, not asserted blindly.
    """

    def test_macro_f1_meets_threshold(self):
        from sklearn.pipeline import Pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import f1_score

        texts, labels = _load_corpus()
        assert len(texts) >= 20, "corpus too small for reliable evaluation"

        train_t, train_l, test_t, test_l = _stratified_split(texts, labels)

        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
        ])
        pipe.fit(train_t, train_l)
        preds = pipe.predict(test_t)

        macro_f1 = f1_score(test_l, preds, average="macro")
        print(f"\nSKLEARN_CLASSIFIER_F1={macro_f1:.4f}")
        assert macro_f1 >= 0.90, (
            f"sklearn sensitivity classifier F1 {macro_f1:.4f} is below threshold 0.90. "
            "Review training data quality or classifier hyperparameters."
        )

    def test_per_class_recall_above_floor(self):
        """Both CLEAN and INJECTION must have recall >= 0.85 (no class collapse)."""
        from sklearn.pipeline import Pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import recall_score

        texts, labels = _load_corpus()
        train_t, train_l, test_t, test_l = _stratified_split(texts, labels)

        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(C=1.0, max_iter=1000, random_state=42)),
        ])
        pipe.fit(train_t, train_l)
        preds = pipe.predict(test_t)

        recalls = recall_score(test_l, preds, average=None, labels=["CLEAN", "INJECTION"])
        for label, recall in zip(["CLEAN", "INJECTION"], recalls):
            assert recall >= 0.85, f"Recall for {label}={recall:.4f} is below 0.85 floor"


# ---------------------------------------------------------------------------
# SensitivityClassifier — sklearn layer wiring
# ---------------------------------------------------------------------------

class TestSensitivityClassifierSklearnLayer:
    def _make_mock_backend(self, label="CLEAN", confidence=0.95):
        from yashigani.inspection.backends.sklearn_backend import SklearnResult
        backend = MagicMock()
        backend.classify.return_value = SklearnResult(
            label=label, confidence=confidence, latency_ms=0.1, needs_llm_pass=False
        )
        return backend

    def test_scan_sklearn_returns_public_on_clean_high_confidence(self):
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier, SensitivityLevel
        clf = SensitivityClassifier(
            enable_sklearn=True,
            sklearn_backend=self._make_mock_backend(label="CLEAN", confidence=0.95),
            enable_ollama=False,
        )
        result = clf.classify("What is the capital of France?")
        assert result.layer_results.get("sklearn") == SensitivityLevel.PUBLIC

    def test_scan_sklearn_returns_public_on_low_confidence(self):
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier, SensitivityLevel
        from yashigani.inspection.backends.sklearn_backend import SklearnResult
        backend = MagicMock()
        backend.classify.return_value = SklearnResult(
            label="INJECTION", confidence=0.3, latency_ms=0.1, needs_llm_pass=True
        )
        clf = SensitivityClassifier(
            enable_sklearn=True,
            sklearn_backend=backend,
            enable_ollama=False,
        )
        result = clf.classify("some text")
        # confidence 0.3 < 0.5 threshold → PUBLIC
        assert result.layer_results.get("sklearn") == SensitivityLevel.PUBLIC

    def test_sklearn_disabled_when_no_backend(self):
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier, SensitivityLevel
        clf = SensitivityClassifier(enable_sklearn=True, sklearn_backend=None, enable_ollama=False)
        result = clf.classify("hello")
        assert "sklearn" not in result.layer_results

    def test_scan_fasttext_alias_delegates_to_scan_sklearn(self):
        """_scan_fasttext must be a backward-compat alias — same result as _scan_sklearn."""
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier, SensitivityLevel
        backend = self._make_mock_backend(label="CLEAN", confidence=0.9)
        clf = SensitivityClassifier(enable_sklearn=True, sklearn_backend=backend, enable_ollama=False)

        triggers_ft: list[str] = []
        triggers_sk: list[str] = []
        level_ft = clf._scan_fasttext("test", triggers_ft)
        backend.classify.reset_mock()
        level_sk = clf._scan_sklearn("test", triggers_sk)
        assert level_ft == level_sk

    def test_legacy_fasttext_backend_kwarg_emits_deprecation_warning(self, caplog):
        """fasttext_backend= kwarg must log a deprecation warning."""
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
        from yashigani.inspection.backends.sklearn_backend import SklearnResult
        backend = MagicMock()
        backend.classify.return_value = SklearnResult(
            label="CLEAN", confidence=0.9, latency_ms=0.0, needs_llm_pass=False
        )
        with caplog.at_level(logging.WARNING, logger="yashigani.optimization.sensitivity_classifier"):
            clf = SensitivityClassifier(fasttext_backend=backend, enable_ollama=False)
        assert any("fasttext_backend is deprecated" in r.message for r in caplog.records)
        assert clf._sklearn is backend

    def test_legacy_enable_fasttext_kwarg_emits_deprecation_warning(self, caplog):
        """enable_fasttext= kwarg must log a deprecation warning."""
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
        with caplog.at_level(logging.WARNING, logger="yashigani.optimization.sensitivity_classifier"):
            clf = SensitivityClassifier(enable_fasttext=False, enable_ollama=False)
        assert any("enable_fasttext is deprecated" in r.message for r in caplog.records)
        assert not clf._enable_sklearn


# ---------------------------------------------------------------------------
# Metrics aliases
# ---------------------------------------------------------------------------

class TestMetricAliases:
    def test_sensitivity_classifier_is_fasttext_alias(self):
        """Canonical aliases point to the same Prometheus counter object."""
        from yashigani.metrics.registry import (
            fasttext_classifications_total,
            sensitivity_classifier_classifications_total,
            fasttext_latency_ms,
            sensitivity_classifier_latency_ms,
        )
        assert fasttext_classifications_total is sensitivity_classifier_classifications_total
        assert fasttext_latency_ms is sensitivity_classifier_latency_ms


# ---------------------------------------------------------------------------
# SklearnBackend model path property
# ---------------------------------------------------------------------------

class TestSklearnBackendProperties:
    def test_model_path_property(self, tmp_path):
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        path = str(tmp_path / "model.joblib")
        b = SklearnBackend(model_path=path)
        assert b.model_path == path

    def test_update_thresholds(self, tmp_path):
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        b = SklearnBackend(model_path=str(tmp_path / "nonexistent.joblib"))
        b.update_thresholds(0.9, 0.5)
        assert b._high_threshold == 0.9
        assert b._low_threshold == 0.5
