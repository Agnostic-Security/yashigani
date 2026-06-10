"""
Yashigani Inspection — Semantic-intent injection classifier sidecar (content-filter v2).

YSG-RISK-057 mitigation (v2.26.0+ register-committed item).

Problem
-------
The v1 MCP content filter (``mcp/_content_filter.py``) is a surface-pattern
heuristic: NFKC -> Cf-strip -> homoglyph -> leet -> separator-collapse ->
regex scan.  It blocks 14/14 of Laura's claimed-pattern bypass classes, but the
**accepted residual** (YSG-RISK-057, CWE-184) is encoded injection —
base64/hex/url/rot13-obfuscated payloads in MCP tool descriptions — that
pattern-matching cannot catch because the scan runs on *decoded text*, not the
encoded blob.

The v2 mitigation is a classifier that evaluates **semantic intent**: "is this
content trying to manipulate the model, regardless of how it is encoded or
phrased?"  This module is that sidecar.

Where it sits
-------------
Defence-in-depth, NOT a replacement.  Three-stage pipeline:

    1. fast heuristic   (mcp/_content_filter.filter_description)  -- always on
    2. semantic-intent  (THIS module)                            -- flag-gated, default OFF
    3. existing LLM      (BackendRegistry deep inspection)        -- request/response path

This sidecar is positioned to run on the MCP tool-description / prompt surface
(stage 2), the exact YSG-RISK-057 residual.  It composes with stage 1: if the
heuristic already rejected, the sidecar need not run (heuristic is cheaper); if
the heuristic passed, the sidecar gets a second, encoding-aware look.

What it consumes
----------------
RAW content AND its decoded views.  It reuses ``pii.decode.decode_views`` (the
F-RT1 decode-before-classify stage, landed 2.25.2) so a base64/hex/url/rot13
payload is normalised to plaintext BEFORE classification.  This is what closes
the encoded-injection gap: the heuristic scans decoded text but never *decodes*;
this sidecar decodes first, then asks the classifier about every view.

What it emits
-------------
A ``SemanticIntentVerdict`` carrying an injection-intent label + score.  The
verdict is MAX-aggregated across all views (raw + decoded): if ANY view looks
like manipulation, the content is flagged.  The caller maps the verdict into the
existing fail-closed decision (reject the tool description / prompt).

Security posture (the sidecar's own LLM reads attacker content)
---------------------------------------------------------------
* The classifier input is HOSTILE.  Content is passed to the backend only as a
  quoted, JSON-escaped literal between USER_CONTENT markers (the existing
  backends already do this) — never as instruction text.
* Structured output is enforced: any deviation from the strict JSON verdict
  schema is treated as a NON-CLEAN signal in prod (fail-closed), never silently
  swallowed as CLEAN.
* Fail-closed: when the sidecar is ENABLED and its backend is unreachable /
  unparseable, the content is treated as suspicious (reject), not passed.  An
  attacker who can DoS the sidecar must NOT thereby disable detection.

Engine-agnostic
---------------
Public strings say "classifier" / "semantic-intent" — never a specific model or
library name.  The model is a local, GPU-served small classifier reused from the
existing Ollama pool / BackendRegistry infra.

GPU / latency honesty
---------------------
This is a per-call local-LLM inference.  On the GPU sizing in
``project_yashigani_llm_capacity_findings`` (qwen2.5:3b-class on an RTX 3060),
a single classify is ~tens-to-low-hundreds of ms and consumes GPU.  Because the
sidecar runs once per *decoded view*, a payload with N decoded views costs up to
N inferences.  Views are bounded by ``pii.decode`` limits (MAX_SEGMENTS,
MAX_DECODE_PASSES, MAX_VIEW_CHARS) and this module additionally caps the number
of views classified (``max_views``).  Default OFF ships dark; operators opt in
once they have GPU headroom.  Needs live-model VM validation (M-gate) for true
latency/recall numbers — the unit suite mocks the backend.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from yashigani.inspection.backend_base import (
    ClassifierBackend,
    BackendUnavailableError,
)
from yashigani.pii.decode import decode_views, DecodeResult

logger = logging.getLogger(__name__)

# Prometheus verdict labels for inspection_semantic_intent_total{verdict}.
_METRIC_ESCALATED = "escalated"
_METRIC_CLEAN = "clean"
_METRIC_ERROR = "error"


def _record_verdict_metric(verdict: "SemanticIntentVerdict") -> None:
    """Emit the dashboard metric for a sidecar decision (reuses the inspection
    metrics registry — no parallel registry).  Never raises: a metrics fault
    must not break the enforcement path.

    Mapping (engine-agnostic):
      escalated — the sidecar flagged injection intent (catches the residual).
      clean     — the sidecar ran and did not escalate.
      error     — fail-closed disposition driven by an indeterminate/unreachable
                  backend (flagged_view in {indeterminate_fail_closed}) — i.e.
                  the sidecar could not reach a real verdict and fail-closed.
    """
    try:
        from yashigani.metrics.registry import inspection_semantic_intent_total

        if verdict.flagged_view == "indeterminate_fail_closed":
            metric_verdict = _METRIC_ERROR
        elif verdict.is_injection:
            metric_verdict = _METRIC_ESCALATED
        else:
            metric_verdict = _METRIC_CLEAN
        inspection_semantic_intent_total.labels(
            verdict=metric_verdict,
            view=(verdict.flagged_view or "none"),
        ).inc()
    except Exception as exc:  # metrics are best-effort; never break enforcement
        logger.debug("semantic-intent: metric emit failed: %s", exc)


# ── Verdict labels ─────────────────────────────────────────────────────────
INTENT_CLEAN = "CLEAN"
INTENT_INJECTION = "INJECTION_INTENT"
# Fail-closed sentinel: the sidecar was enabled but could not reach a verdict.
INTENT_INDETERMINATE = "INDETERMINATE"

# Backend ClassifierResult labels that count as "injection intent" for the
# semantic-intent decision.  CLEAN is the only non-injection label.
_INJECTION_BACKEND_LABELS = frozenset(
    {"PROMPT_INJECTION_ONLY", "CREDENTIAL_EXFIL"}
)

# Feature-flag env var.  Default OFF (ships dark) per YSG-RISK-057 foundation slice.
_FLAG_ENV = "YASHIGANI_SEMANTIC_INTENT_SIDECAR"

# How many decoded views (raw + decoded) to classify per call.  Bounds GPU cost.
_DEFAULT_MAX_VIEWS = 8

# Score the sidecar assigns to a "suspicious_blob" (encoded, high-entropy,
# undecodable) view when no backend verdict is available for it.  This is the
# F-RT1 silent-pass guard carried into the injection-intent decision: an
# encoded blob that will not decode is itself suspicious.
_SUSPICIOUS_BLOB_SCORE = 0.90


def sidecar_enabled() -> bool:
    """True when the semantic-intent sidecar is enabled via feature flag.

    Default OFF.  Accepts 1/true/yes/on (case-insensitive).  Reading the flag
    at call time (not import time) lets tests and admins toggle without reload.
    """
    return os.getenv(_FLAG_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class ViewVerdict:
    """Per-view classification outcome (one decoded view of the input)."""
    view_name: str          # "raw" | "base64" | "hex" | "url" | "rot13" | ...
    label: str              # INTENT_CLEAN | INTENT_INJECTION | INTENT_INDETERMINATE
    score: float            # 0.0-1.0 injection-intent score
    segment: str = ""       # masked encoded token this view came from (audit-safe)


@dataclass
class SemanticIntentVerdict:
    """
    Aggregate semantic-intent verdict for a single piece of content.

    Attributes
    ----------
    label:
        INTENT_CLEAN     — no view showed injection intent.
        INTENT_INJECTION — at least one view (raw or decoded) showed intent.
        INTENT_INDETERMINATE — sidecar enabled but could not reach a verdict
                               AND fail-closed is not in force (dev only); in
                               prod this never surfaces — fail_closed forces
                               INTENT_INJECTION instead.
    score:
        MAX injection-intent score across all classified views (0.0-1.0).
    flagged_view:
        The view_name that drove the verdict (the highest-scoring view).
    suspicious_blob:
        Propagated from decode_views — an encoded, high-entropy, undecodable
        token was present (F-RT1 silent-pass guard).
    view_verdicts:
        Per-view detail (audit / debugging).  Encoded segments are masked.
    latency_ms:
        Wall-clock time the sidecar took (sum of backend calls).
    skipped:
        True when the sidecar did not run (flag OFF) — caller should ignore.
    """
    label: str
    score: float
    flagged_view: str = "raw"
    suspicious_blob: bool = False
    view_verdicts: list[ViewVerdict] = field(default_factory=list)
    latency_ms: int = 0
    skipped: bool = False

    @property
    def is_injection(self) -> bool:
        """True when the content should be treated as an injection attempt."""
        return self.label == INTENT_INJECTION


class SemanticIntentSidecar:
    """
    Semantic-intent injection classifier (content-filter v2 / YSG-RISK-057).

    Wraps a ``ClassifierBackend`` (reuse the Ollama pool / BackendRegistry's
    underlying backend) and decodes-before-classifying via ``pii.decode``.

    The sidecar NEVER trusts its own LLM to fail-open: a backend error, an
    unparseable response, or an indeterminate verdict resolves to INJECTION
    when ``fail_closed`` is True (default — and forced True in prod/staging).
    """

    def __init__(
        self,
        backend: ClassifierBackend,
        *,
        injection_threshold: float = 0.50,
        max_views: int = _DEFAULT_MAX_VIEWS,
        fail_closed: bool = True,
    ) -> None:
        """
        Parameters
        ----------
        backend:
            Any ClassifierBackend (OllamaBackend, OllamaPool, or a mock in
            tests).  classify() returns a ClassifierResult(label, confidence).
        injection_threshold:
            Backend confidence at/above which an injection-labelled view counts
            as injection intent.  Below the threshold, an injection label is
            downgraded toward CLEAN (low-confidence noise).
        max_views:
            Cap on decoded views classified per call (GPU-cost bound).
        fail_closed:
            When True (default), any unreachable/unparseable/indeterminate
            outcome resolves to INTENT_INJECTION.  Forced True in
            production/staging by ``from_env``.
        """
        self._backend = backend
        self._threshold = injection_threshold
        self._max_views = max(1, int(max_views))
        self._fail_closed = bool(fail_closed)

    @classmethod
    def from_env(cls, backend: ClassifierBackend) -> "SemanticIntentSidecar":
        """Build with env-derived posture.  Fail-closed forced in prod/staging."""
        env = os.getenv("YASHIGANI_ENV", "").strip().lower()
        fail_closed = True if env in {"production", "staging"} else _flag_truthy(
            os.getenv("YASHIGANI_SEMANTIC_INTENT_FAIL_CLOSED", "1")
        )
        try:
            threshold = float(os.getenv("YASHIGANI_SEMANTIC_INTENT_THRESHOLD", "0.5"))
        except ValueError:
            threshold = 0.5
        return cls(
            backend,
            injection_threshold=max(0.0, min(1.0, threshold)),
            fail_closed=fail_closed,
        )

    # ── Public API ─────────────────────────────────────────────────────────

    def evaluate(self, content: str) -> SemanticIntentVerdict:
        """
        Evaluate *content* for semantic injection intent across raw + decoded
        views.  Treats *content* as hostile.

        Returns a SemanticIntentVerdict.  When the feature flag is OFF, returns
        a skipped verdict (label=CLEAN, skipped=True) — the caller relies on the
        v1 heuristic alone.
        """
        if not sidecar_enabled():
            return SemanticIntentVerdict(
                label=INTENT_CLEAN, score=0.0, skipped=True
            )

        start_ms = int(time.monotonic() * 1000)

        # Decode-before-classify (F-RT1 reuse): raw view + decoded views.
        # decode_views never raises.
        try:
            decoded: DecodeResult = decode_views(content)
        except Exception as exc:  # defence-in-depth; decode_views is no-raise
            logger.error("semantic-intent: decode_views failed: %s", exc)
            return self._fail_closed_verdict("raw", start_ms)

        view_verdicts: list[ViewVerdict] = []
        best_score = 0.0
        best_label = INTENT_CLEAN
        best_view = "raw"
        indeterminate_seen = False

        for view in decoded.views[: self._max_views]:
            vv = self._classify_view(view.view_name, view.text, view.segment)
            view_verdicts.append(vv)
            if vv.label == INTENT_INDETERMINATE:
                indeterminate_seen = True
            if vv.score > best_score:
                best_score = vv.score
                best_label = vv.label
                best_view = vv.view_name

        # F-RT1 silent-pass guard: an encoded, high-entropy, undecodable blob is
        # itself suspicious even if no view classified as injection.
        if decoded.suspicious_blob and best_score < _SUSPICIOUS_BLOB_SCORE:
            best_score = _SUSPICIOUS_BLOB_SCORE
            best_label = INTENT_INJECTION
            best_view = "suspicious_blob"
            view_verdicts.append(ViewVerdict(
                view_name="suspicious_blob",
                label=INTENT_INJECTION,
                score=_SUSPICIOUS_BLOB_SCORE,
                segment=(decoded.flagged_tokens[0] if decoded.flagged_tokens else ""),
            ))

        latency_ms = int(time.monotonic() * 1000) - start_ms

        # Fail-closed: if any view was indeterminate and nothing else flagged
        # injection, treat the whole thing as injection in fail-closed mode.
        if indeterminate_seen and best_label != INTENT_INJECTION and self._fail_closed:
            best_label = INTENT_INJECTION
            best_score = max(best_score, 1.0)
            best_view = "indeterminate_fail_closed"

        verdict = SemanticIntentVerdict(
            label=best_label,
            score=best_score,
            flagged_view=best_view,
            suspicious_blob=decoded.suspicious_blob,
            view_verdicts=view_verdicts,
            latency_ms=latency_ms,
            skipped=False,
        )
        _record_verdict_metric(verdict)
        return verdict

    # ── Internal ───────────────────────────────────────────────────────────

    def _classify_view(self, view_name: str, text: str, segment: str) -> ViewVerdict:
        """Classify a single view.  Maps backend result -> injection-intent.

        Backend input is hostile; the backend is responsible for quoting it as
        a literal (existing backends do).  A backend error or unparseable
        result becomes INTENT_INDETERMINATE here; the aggregate fail-closed
        logic in evaluate() decides the final disposition.
        """
        if not text:
            return ViewVerdict(view_name, INTENT_CLEAN, 0.0, segment)
        try:
            result = self._backend.classify(text)
        except BackendUnavailableError as exc:
            logger.warning(
                "semantic-intent: backend unavailable for view=%s: %s",
                view_name, exc,
            )
            return ViewVerdict(view_name, INTENT_INDETERMINATE, 0.0, segment)
        except Exception as exc:  # backend must not raise non-BUE, but be safe
            logger.error(
                "semantic-intent: backend raised %s for view=%s",
                type(exc).__name__, view_name,
            )
            return ViewVerdict(view_name, INTENT_INDETERMINATE, 0.0, segment)

        label = getattr(result, "label", "") or ""
        confidence = float(getattr(result, "confidence", 0.0) or 0.0)
        confidence = max(0.0, min(1.0, confidence))

        if label in _INJECTION_BACKEND_LABELS and confidence >= self._threshold:
            return ViewVerdict(view_name, INTENT_INJECTION, confidence, segment)
        # Injection-labelled but below threshold, or CLEAN, or unknown label.
        # An unknown label in fail-closed mode is indeterminate (don't treat a
        # garbage label as CLEAN — that is the jailbroken-model bypass).
        if label not in _INJECTION_BACKEND_LABELS and label != "CLEAN":
            return ViewVerdict(view_name, INTENT_INDETERMINATE, 0.0, segment)
        return ViewVerdict(view_name, INTENT_CLEAN, confidence if label != "CLEAN" else 0.0, segment)

    def _fail_closed_verdict(self, view: str, start_ms: int) -> SemanticIntentVerdict:
        label = INTENT_INJECTION if self._fail_closed else INTENT_INDETERMINATE
        verdict = SemanticIntentVerdict(
            label=label,
            # flagged_view marks this as a fail-closed-on-error disposition so
            # the metric records it under verdict="error", not "escalated".
            flagged_view="indeterminate_fail_closed" if self._fail_closed else view,
            score=1.0 if self._fail_closed else 0.0,
            latency_ms=int(time.monotonic() * 1000) - start_ms,
            skipped=False,
        )
        _record_verdict_metric(verdict)
        return verdict


def _flag_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}
