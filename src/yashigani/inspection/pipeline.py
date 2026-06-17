"""
Yashigani Inspection — Main pipeline orchestrator.
Coordinates pre-masking → classification → disposition → audit.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Callable

from yashigani.audit.masking import CredentialMasker
from yashigani.inspection.classifier import (
    PromptInjectionClassifier,
    LABEL_CLEAN,
    LABEL_CREDENTIAL_EXFIL,
    LABEL_PROMPT_INJECTION_ONLY,
)
from yashigani.inspection.sanitizer import sanitize, SanitizationResult

logger = logging.getLogger(__name__)

_DEFAULT_SANITIZE_THRESHOLD = 0.85


def _record_classification(classification: str, severity: str) -> None:
    """Emit the inspection-pipeline verdict metric (label = threat category,
    severity = ''/HIGH/CRITICAL).

    This is the metric the Security Overview / Agent Activity dashboards and the
    CredentialExfil / PromptInjection alerts query. Lazy import avoids a
    metrics<->pipeline import cycle; metrics must never break a request.
    """
    try:
        from yashigani.metrics.registry import inspection_classifications_total
        inspection_classifications_total.labels(
            label=classification, severity=severity
        ).inc()
    except Exception:  # pragma: no cover — never fail a request on metrics
        pass


@dataclass
class PipelineResult:
    request_id: str
    action: str                     # PASS | SANITIZED | DISCARDED
    clean_query: Optional[str]      # forwarded content; None if discarded
    classification: str             # CLEAN | CREDENTIAL_EXFIL | PROMPT_INJECTION_ONLY
    severity: str                   # "" | HIGH | CRITICAL
    confidence: float
    admin_alert: Optional[dict]
    user_alert: Optional[dict]
    audit_fields: dict


class InspectionPipeline:
    """
    Full inspection pipeline for inbound queries.

    Flow:
    1. Pre-mask credentials in content (CHS masker)
    2. Classify with Qwen3.5 (local only) via classifier or backend_registry
    3. Apply disposition based on label + confidence threshold
    4. Build admin/user alerts and audit record

    If backend_registry is provided it takes precedence over the legacy
    classifier; the classifier is kept for backward-compat callers that
    do not use the registry.
    """

    def __init__(
        self,
        classifier: PromptInjectionClassifier,
        sanitize_threshold: float = _DEFAULT_SANITIZE_THRESHOLD,
        on_audit: Optional[Callable[[str, dict], None]] = None,
        backend_registry=None,  # Optional[BackendRegistry]
    ) -> None:
        self._classifier = classifier
        self._backend_registry = backend_registry
        self._threshold = sanitize_threshold
        self._masker = CredentialMasker()
        self._on_audit = on_audit or (lambda name, data: None)

    def process(
        self,
        raw_query: str,
        session_id: str,
        agent_id: str,
        user_id: str,
    ) -> PipelineResult:
        """
        Process an inbound query through the full inspection pipeline.
        Returns PipelineResult with the action and forwarding content.
        """
        request_id = str(uuid.uuid4())

        # Step 1: Mask credentials before sending to classifier
        try:
            masked_query = self._masker.mask_string(raw_query)
        except Exception as exc:
            logger.warning("CHS masker failed (%s) — using raw query for classification", exc)
            masked_query = raw_query

        # Step 2: Classify — use backend_registry if available, else legacy classifier
        result: Any
        if self._backend_registry is not None:
            backend_result = self._backend_registry.classify(masked_query, request_id=request_id)
            # Adapt BackendRegistry ClassifierResult to the legacy classifier shape
            # Pipeline disposition only needs .label and .confidence; wrap in a simple object
            result = _BackendResultAdapter(
                label=backend_result.label,
                confidence=backend_result.confidence,
            )
        else:
            result = self._classifier.classify(masked_query)

        # Step 3: Disposition
        if result.label == LABEL_CLEAN:
            pipeline_result = self._pass_through(request_id, raw_query, session_id, agent_id)
        elif result.label == LABEL_CREDENTIAL_EXFIL:
            pipeline_result = self._handle_credential_exfil(
                request_id, raw_query, masked_query, result,
                session_id, agent_id, user_id,
            )
        else:  # PROMPT_INJECTION_ONLY
            pipeline_result = self._handle_injection_only(
                request_id, result, session_id, agent_id, user_id,
            )

        # Emit the designed pipeline-verdict metric for every disposition.
        _record_classification(pipeline_result.classification, pipeline_result.severity)
        return pipeline_result

    def update_threshold(self, threshold: float) -> None:
        """Admin-configurable sanitization confidence threshold."""
        if not 0.70 <= threshold <= 0.99:
            raise ValueError("Threshold must be between 0.70 and 0.99")
        self._threshold = threshold

    def _dispatch_credential_exfil_alert(
        self,
        request_id: str,
        session_id: str,
        agent_id: str,
        action: str,
        confidence: float,
    ) -> None:
        """
        Fire-and-forget webhook alert for credential exfil detections (v0.7.1).
        Only dispatches if sinks are configured and `alert_on_credential_exfil` is True.
        Never raises — failures are logged by the dispatcher.
        """
        try:
            from yashigani.backoffice.state import backoffice_state
            from yashigani.alerts import get_dispatcher
            from yashigani.alerts.base import AlertPayload

            alert_config = getattr(backoffice_state, "alert_config", None)
            if alert_config is not None and not getattr(alert_config, "alert_on_credential_exfil", True):
                return

            dispatcher = get_dispatcher()
            if not dispatcher.has_sinks:
                return

            payload = AlertPayload(
                severity="critical",
                title="Yashigani — Credential Exfiltration Detected",
                body=(
                    f"A credential exfiltration attempt was detected and {action.lower()}. "
                    f"Request ID: {request_id} | Agent: {agent_id} | "
                    f"Session: {session_id} | Confidence: {confidence:.2f}"
                ),
                event_id=request_id,
                agent_id=agent_id,
                source_component="yashigani.inspection.pipeline",
            )
            dispatcher.dispatch_sync(payload)
        except Exception as exc:
            logger.error("_dispatch_credential_exfil_alert: unexpected error: %s", exc)

    # -- Disposition handlers ------------------------------------------------

    def _pass_through(
        self, request_id: str, raw_query: str,
        session_id: str, agent_id: str,
    ) -> PipelineResult:
        return PipelineResult(
            request_id=request_id,
            action="PASS",
            clean_query=raw_query,
            classification=LABEL_CLEAN,
            severity="",
            confidence=1.0,
            admin_alert=None,
            user_alert=None,
            audit_fields={},
        )

    def _handle_credential_exfil(
        self, request_id: str, raw_query: str, masked_query: str,
        classifier_result, session_id: str, agent_id: str, user_id: str,
    ) -> PipelineResult:
        action = "DISCARDED"
        clean_query = None
        sanitized = False

        if classifier_result.confidence >= self._threshold:
            san: SanitizationResult = sanitize(
                masked_query, classifier_result.detected_payload_spans
            )
            if san.success and san.clean_query:
                action = "SANITIZED"
                clean_query = san.clean_query
                sanitized = True

        admin_alert = {
            "alert_type": "CREDENTIAL_EXFIL_DETECTED",
            "severity": "CRITICAL",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "classifier_confidence": classifier_result.confidence,
            "threshold_applied": self._threshold,
            "action_taken": action,
            "sanitized": sanitized,
        }
        user_alert = _build_user_alert(request_id, action, sanitized, LABEL_CREDENTIAL_EXFIL)

        audit = {
            "event_type": "PROMPT_INJECTION_DETECTED",
            "classification": LABEL_CREDENTIAL_EXFIL,
            "severity": "CRITICAL",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "user_id": user_id,
            "action_taken": action,
            "sanitized": sanitized,
            "confidence_score": classifier_result.confidence,
            "threshold_applied": self._threshold,
            "admin_alerted": True,
            "user_alerted": True,
            "raw_query_logged": False,
            "content_hash": _content_hash(raw_query),
        }
        self._on_audit("PROMPT_INJECTION_DETECTED", audit)

        # Dispatch webhook alert if sinks are configured (v0.7.1 P2-3)
        self._dispatch_credential_exfil_alert(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            action=action,
            confidence=classifier_result.confidence,
        )

        return PipelineResult(
            request_id=request_id,
            action=action,
            clean_query=clean_query,
            classification=LABEL_CREDENTIAL_EXFIL,
            severity="CRITICAL",
            confidence=classifier_result.confidence,
            admin_alert=admin_alert,
            user_alert=user_alert,
            audit_fields=audit,
        )

    def _handle_injection_only(
        self, request_id: str, classifier_result,
        session_id: str, agent_id: str, user_id: str,
    ) -> PipelineResult:
        admin_alert = {
            "alert_type": "PROMPT_INJECTION_DETECTED",
            "severity": "HIGH",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "classifier_confidence": classifier_result.confidence,
            "action_taken": "DISCARDED",
            "sanitized": False,
            "admin_alerted": True,
        }
        user_alert = _build_user_alert(request_id, "DISCARDED", False, LABEL_PROMPT_INJECTION_ONLY)

        audit = {
            "event_type": "PROMPT_INJECTION_DETECTED",
            "classification": LABEL_PROMPT_INJECTION_ONLY,
            "severity": "HIGH",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "user_id": user_id,
            "action_taken": "DISCARDED",
            "sanitized": False,
            "confidence_score": classifier_result.confidence,
            "admin_alerted": True,
            "user_alerted": True,
            "raw_query_logged": False,
        }
        self._on_audit("PROMPT_INJECTION_DETECTED", audit)

        return PipelineResult(
            request_id=request_id,
            action="DISCARDED",
            clean_query=None,
            classification=LABEL_PROMPT_INJECTION_ONLY,
            severity="HIGH",
            confidence=classifier_result.confidence,
            admin_alert=admin_alert,
            user_alert=user_alert,
            audit_fields=audit,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_user_alert(
    request_id: str,
    action: str,
    sanitized: bool,
    classification: str = LABEL_PROMPT_INJECTION_ONLY,
) -> dict:
    """Unified layman alert for request-leg inspection blocks (#4, direction=from_you).

    Uses the shared yashigani.common.user_alert envelope so the same plain-English
    shape is returned at every enforcement point (educate + deter).
    """
    from yashigani.common.user_alert import (
        build_alert,
        ACTION_BLOCKED,
        ACTION_MODIFIED,
        DIRECTION_FROM_YOU,
    )

    is_exfil = classification == LABEL_CREDENTIAL_EXFIL
    if action == "SANITIZED":
        act = ACTION_MODIFIED
        reason = (
            "Your message appeared to try to extract credentials or secrets; the "
            "risky part was removed before the request continued."
            if is_exfil
            else "Your message was modified to remove content that violates policy "
            "before it continued."
        )
    else:
        act = ACTION_BLOCKED
        reason = (
            "Your message appeared to try to extract credentials or secrets, so it "
            "was blocked and not sent to the assistant."
            if is_exfil
            else "Your message looked like an attempt to override the assistant's "
            "instructions (a prompt injection), so it was blocked and not sent to "
            "the assistant."
        )
    rule = (
        "Credential exfiltration (your request)"
        if is_exfil
        else "Prompt injection (your request)"
    )
    return build_alert(
        act, reason, rule=rule, direction=DIRECTION_FROM_YOU, request_id=request_id
    )


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Adapter — bridges BackendRegistry ClassifierResult to the pipeline's
# internal duck-typed classifier result shape (label, confidence, and a
# no-op detected_payload_spans for the sanitizer path).
# ---------------------------------------------------------------------------

class _BackendResultAdapter:
    """Minimal adapter so BackendRegistry results work in disposition handlers."""

    def __init__(self, label: str, confidence: float) -> None:
        self.label = label
        self.confidence = confidence
        self.exfil_indicators = label == LABEL_CREDENTIAL_EXFIL
        self.detected_payload_spans: list = []


# ---------------------------------------------------------------------------
# Response inspection — Phase 2 (v0.9.0 F-01)
# ---------------------------------------------------------------------------

# Verdict constants for response inspection
RESPONSE_VERDICT_CLEAN = "CLEAN"
RESPONSE_VERDICT_FLAGGED = "FLAGGED"
RESPONSE_VERDICT_BLOCKED = "BLOCKED"


@dataclass
class ResponseInspectionConfig:
    """
    Per-agent configuration for the response inspection pipeline.

    Fields:
        enabled             Toggle the pipeline entirely.
        classifier_only     Skip LLM fallback — classify with the first-pass classifier only.
                            Faster but lower recall on novel injection patterns.
        blocked_action      HTTP status code to return when a response is BLOCKED.
                            Must be "502" (upstream tainted) per the security design.
                            "403" is reserved for request-path blocks.
        exempt_content_types
                            Content-Type values that bypass response inspection.
                            Empty by default — all content types are inspected.
                            Add entries only when a content type is provably safe and
                            false-positive cost outweighs the inspection risk.
                            Each addition is an explicit trust assumption; document the reason.
    """
    enabled: bool = True
    classifier_only: bool = False
    blocked_action: str = "502"
    exempt_content_types: list[str] = field(
        default_factory=list
    )


@dataclass
class ResponseInspectionResult:
    request_id: str
    verdict: str                    # CLEAN | FLAGGED | BLOCKED
    confidence: float
    skipped: bool                   # True when inspection was bypassed (disabled/exempt)
    skip_reason: Optional[str]      # "disabled" | "exempt_content_type" | None
    audit_fields: dict
    # v2.24.1 — GAP-3 / SEC-5: response-content sensitivity classification.
    # When pipeline is enabled and runs, this is the SensitivityLevel of the
    # response body (not the prompt).  Defaults to PUBLIC (most permissive)
    # so callers that do not inspect responses see conservative-safe behaviour.
    response_sensitivity: str = "PUBLIC"  # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED


class ResponseInspectionPipeline:
    """
    Response inspection pipeline — inspects tool/upstream responses before
    they are returned to the calling agent.

    Threat model:
        A malicious document (or tool response) may embed natural-language
        instructions designed to redirect agent behaviour — indirect prompt
        injection. This pipeline applies the same classifier + LLM fallback
        chain used for request inspection, but operates on the *response body*
        rather than the agent query.

    Disposition:
        CLEAN   — response is forwarded as-is.
        FLAGGED — response is forwarded but the audit event is written and
                  an X-Yashigani-Response-Verdict header is attached.
        BLOCKED — response is suppressed; a 502 is returned to the agent
                  (versus 403 for request blocks, which signal a client error).

    The raw response body is never stored in the audit log. A SHA-256 hash
    is recorded instead (ASVS V7.1 — audit log integrity).

    v2.24.1 — GAP-3 / SEC-5:
        Pass a `sensitivity_classifier` (SensitivityClassifier instance) to
        have the pipeline classify response-*content* sensitivity in addition to
        the injection-verdict check.  When provided, `ResponseInspectionResult`
        carries a `response_sensitivity` field (PUBLIC…RESTRICTED) derived from
        the response body, independent of the prompt's sensitivity level.
        When absent the field defaults to "PUBLIC" (safe fallback — OPA will
        fall back to prompt sensitivity per the updated v1_routing.rego rule).
    """

    def __init__(
        self,
        classifier: PromptInjectionClassifier,
        config: Optional[ResponseInspectionConfig] = None,
        on_audit: Optional[Callable[[str, dict], None]] = None,
        backend_registry=None,  # Optional[BackendRegistry]
        sensitivity_classifier=None,  # Optional[SensitivityClassifier]
    ) -> None:
        self._classifier = classifier
        self._backend_registry = backend_registry
        self._config = config or ResponseInspectionConfig()
        self._on_audit = on_audit or (lambda name, data: None)
        # v2.24.1 — GAP-3: optional second classifier for response-content sensitivity
        self._sensitivity_classifier = sensitivity_classifier

    def inspect(
        self,
        response_body: str,
        content_type: str,
        request_id: str,
        session_id: str,
        agent_id: str,
    ) -> ResponseInspectionResult:
        """
        Inspect an upstream response body.

        Parameters:
            response_body   Decoded text of the upstream response.
            content_type    Content-Type header value from the upstream response.
            request_id      Correlation ID from the originating gateway request.
            session_id      Agent session identifier.
            agent_id        Registered agent identifier.

        Returns:
            ResponseInspectionResult with the verdict and audit fields.
        """
        cfg = self._config

        # Fast path — pipeline disabled
        if not cfg.enabled:
            return ResponseInspectionResult(
                request_id=request_id,
                verdict=RESPONSE_VERDICT_CLEAN,
                confidence=1.0,
                skipped=True,
                skip_reason="disabled",
                audit_fields={},
                response_sensitivity="PUBLIC",
            )

        # Fast path — exempt content type
        ct_base = content_type.split(";")[0].strip().lower()
        for exempt in cfg.exempt_content_types:
            if ct_base == exempt.lower():
                return ResponseInspectionResult(
                    request_id=request_id,
                    verdict=RESPONSE_VERDICT_CLEAN,
                    confidence=1.0,
                    skipped=True,
                    skip_reason="exempt_content_type",
                    audit_fields={},
                    response_sensitivity="PUBLIC",
                )

        # v2.24.1 — GAP-3 / SEC-5: classify response-content sensitivity.
        # Runs here (before injection check) so sensitivity is always populated
        # even when the verdict is CLEAN.  Fail-safe: any exception defaults to
        # PUBLIC so callers still get a usable result; OPA falls back to prompt
        # sensitivity via the MAX() rule in v1_routing.rego.
        response_sensitivity_value = "PUBLIC"
        if self._sensitivity_classifier is not None:
            try:
                # F-RT1 (red-team verified 2026-05-30): decode-before-classify so an
                # encoded sensitive value in the response body elevates the response
                # sensitivity (feeds the response-leg OPA ceiling), instead of being
                # a silent PUBLIC pass.  classify_decoded is a superset of classify
                # for non-encoded text.  getattr keeps older classifier stubs working.
                _classify = getattr(
                    self._sensitivity_classifier,
                    "classify_decoded",
                    self._sensitivity_classifier.classify,
                )
                sens_result = _classify(response_body)
                response_sensitivity_value = sens_result.level.value
            except Exception as exc:
                logger.warning(
                    "ResponseInspectionPipeline: sensitivity_classifier failed "
                    "(request_id=%s): %s — defaulting to PUBLIC",
                    request_id, exc,
                )

        # Classify — backend_registry takes precedence over legacy classifier
        classifier_result: Any
        if self._backend_registry is not None:
            backend_result = self._backend_registry.classify(
                response_body, request_id=request_id
            )
            classifier_result = _BackendResultAdapter(
                label=backend_result.label,
                confidence=backend_result.confidence,
            )
        else:
            classifier_result = self._classifier.classify(response_body)

        # Disposition
        if classifier_result.label == LABEL_CLEAN:
            return ResponseInspectionResult(
                request_id=request_id,
                verdict=RESPONSE_VERDICT_CLEAN,
                confidence=classifier_result.confidence,
                skipped=False,
                skip_reason=None,
                audit_fields={},
                response_sensitivity=response_sensitivity_value,
            )

        # Any non-CLEAN label is a potential injection attempt
        verdict = (
            RESPONSE_VERDICT_BLOCKED
            if cfg.blocked_action == "502"
            else RESPONSE_VERDICT_FLAGGED
        )

        action_taken = "502_returned" if verdict == RESPONSE_VERDICT_BLOCKED else "flagged_only"
        content_hash = _content_hash(response_body)

        audit = {
            "event_type": "RESPONSE_INJECTION_DETECTED",
            "verdict": verdict,
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "classification": classifier_result.label,
            "confidence_score": classifier_result.confidence,
            "action_taken": action_taken,
            "content_type": content_type,
            "response_content_hash": content_hash,
            "classifier_only_mode": cfg.classifier_only,
            "response_sensitivity": response_sensitivity_value,
        }
        self._on_audit("RESPONSE_INJECTION_DETECTED", audit)

        return ResponseInspectionResult(
            request_id=request_id,
            verdict=verdict,
            confidence=classifier_result.confidence,
            skipped=False,
            skip_reason=None,
            audit_fields=audit,
            response_sensitivity=response_sensitivity_value,
        )

    def update_config(self, config: ResponseInspectionConfig) -> None:
        """Replace the active config. Admin-callable."""
        self._config = config
