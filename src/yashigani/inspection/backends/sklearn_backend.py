"""
sklearn first-pass content classifier — Phase 12 (v2.23.3 fasttext replacement).

Model trained at image build time from data/fasttext/training_data.txt
and serialised as a joblib pipeline at /app/models/sensitivity_classifier.joblib.

Replaces fasttext-wheel (last upload 2020-09-03, archived 2024-03-22, ABI-pins
Python ≤3.12). scikit-learn ships wheels for Python 3.13/3.14 and is actively
maintained.

Pipeline: TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True)
          → LogisticRegression(C=1.0, max_iter=1000)

Measured F1 (macro, 80/20 split, seed=42 on 220 examples):
  LogisticRegression: 0.9545  PASS >= 0.90
  LinearSVC:          0.8408  (below threshold — LR chosen)

Inference latency: ~0.014 ms/sample (TF-IDF vectorise + linear predict).
Model artifact: ~28 KB compressed joblib (vs fasttext .bin which was ~1-2 MB).

Threshold calibration (v2.23.3 — Laura CVA finding LAURA-CVA-V233-SKLEARN #1 +
  re-probe LAURA-CVA-V233-SKLEARN-REPROBE 2026-05-10T15:19:52Z):
  LogisticRegression.predict_proba() returns calibrated simplex probabilities
  summing to 1.0. On a balanced 2-class problem the maximum observable
  INJECTION-class confidence is ~0.77–0.79 — the inherited HIGH_THRESHOLD=0.8 from
  fasttext (which returned raw sigmoid scores routinely > 0.8) was unreachable,
  causing Layer 2 to return UNCERTAIN for 100% of injection inputs.

  Round 1 fix: HIGH_THRESHOLD=0.50 (natural LR decision boundary). Fixed TPR=0.00
  regression but introduced OOD FPR=0.35 on enterprise admin queries (7/20 legitimate
  queries flagged RESTRICTED — see Laura re-probe §5).

  Round 2 calibration: HIGH_THRESHOLD=0.57 — Laura empirical threshold sweep:
    thresh=0.50: OOD FPR=0.35 (7/20)  INJECTION recall=0.9818 (108/110)
    thresh=0.57: OOD FPR=0.05 (1/20)  INJECTION recall=0.9455 (104/110)
    thresh=0.60: OOD FPR=0.00 (0/20)  INJECTION recall=0.9091 (100/110)
  0.57 balances recall and OOD FPR. A1 verbatim 8/8 and A2 novel 9/10 still detected.
  6 corpus samples (conf 0.50–0.57) route to ollama (Layer 3 defence-in-depth).
  In-dist FPR: ~0.027 (3/110 corpus clean samples) — acceptable.

  Corpus expansion (50–100 enterprise admin clean samples) is the long-term fix;
  deferred to post-private-flip backlog (no v2.24.0 milestone).

Two-stage pipeline:
  confidence >= high_threshold (0.50) → direct decision (CLEAN or UNSAFE)
  confidence < high_threshold         → UNCERTAIN → LLM second-pass
  model unavailable                   → UNCERTAIN → LLM second-pass

If model unavailable, returns UNCERTAIN (always routes to LLM).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

MODEL_PATH = os.getenv("SKLEARN_MODEL_PATH", "/app/models/sensitivity_classifier.joblib")
DEFAULT_HIGH_THRESHOLD = 0.57  # Calibrated per Laura re-probe LAURA-CVA-V233-SKLEARN-REPROBE 2026-05-10: OOD FPR 0.35→0.05, INJECTION recall 0.9455 (see module docstring)
DEFAULT_LOW_THRESHOLD = 0.4


@dataclass
class SklearnResult:
    label: str           # "CLEAN" | "UNSAFE" | "UNCERTAIN"
    confidence: float
    latency_ms: float
    needs_llm_pass: bool


class SklearnBackend:
    name = "sklearn"

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        high_threshold: float = DEFAULT_HIGH_THRESHOLD,
        low_threshold: float = DEFAULT_LOW_THRESHOLD,
    ) -> None:
        self._model_path = model_path
        self._high_threshold = high_threshold
        self._low_threshold = low_threshold
        self._pipeline = None
        self._available = False
        self._load_model()

    def _load_model(self) -> None:
        if not os.path.exists(self._model_path):
            logger.warning(
                "sklearn model not found at %s — disabled. All requests use LLM second-pass.",
                self._model_path,
            )
            return
        try:
            import joblib  # noqa: PLC0415 — intentional lazy import
            self._pipeline = joblib.load(self._model_path)
            self._available = True
            logger.info("sklearn sensitivity model loaded from %s", self._model_path)
        except ImportError:
            logger.warning("joblib not installed — sklearn classifier disabled")
        except Exception as exc:
            logger.error("sklearn model load error: %s", exc)

    @property
    def model_path(self) -> str:
        return self._model_path

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, text: str) -> SklearnResult:
        """Classify text. Returns SklearnResult. Never raises."""
        if not self._available or self._pipeline is None:
            return SklearnResult(label="UNCERTAIN", confidence=0.0, latency_ms=0.0, needs_llm_pass=True)

        start = time.monotonic()
        try:
            clean_text = text.replace("\n", " ").replace("\r", " ").strip()
            if not clean_text:
                return SklearnResult(label="CLEAN", confidence=1.0, latency_ms=0.0, needs_llm_pass=False)

            proba = self._pipeline.predict_proba([clean_text])[0]
            classes = self._pipeline.classes_
            best_idx = int(proba.argmax())
            primary_label_raw = str(classes[best_idx]).upper()
            confidence = float(proba[best_idx])

            latency_ms = (time.monotonic() - start) * 1000

            self._record_metrics(primary_label_raw, confidence, latency_ms)

            if confidence >= self._high_threshold:
                label = "CLEAN" if "CLEAN" in primary_label_raw else "UNSAFE"
                return SklearnResult(label=label, confidence=confidence, latency_ms=latency_ms, needs_llm_pass=False)
            else:
                return SklearnResult(label="UNCERTAIN", confidence=confidence, latency_ms=latency_ms, needs_llm_pass=True)

        except Exception as exc:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("sklearn classify error: %s", exc)
            return SklearnResult(label="UNCERTAIN", confidence=0.0, latency_ms=latency_ms, needs_llm_pass=True)

    def _record_metrics(self, label: str, confidence: float, latency_ms: float) -> None:
        try:
            from yashigani.metrics.registry import sensitivity_classifier_classifications_total, sensitivity_classifier_latency_ms
            result = "clean" if "CLEAN" in label else "unsafe"
            if confidence < self._high_threshold:
                result = "uncertain"
            sensitivity_classifier_classifications_total.labels(result=result, backend="sklearn").inc()
            sensitivity_classifier_latency_ms.observe(latency_ms)
        except Exception:
            pass

    def update_thresholds(self, high: float, low: float) -> None:
        self._high_threshold = high
        self._low_threshold = low
        logger.info("sklearn thresholds updated: high=%.2f low=%.2f", high, low)
