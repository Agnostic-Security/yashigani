"""
Yashigani Inspection — Backend registry with fallback chain.

Manages the active classifier backend and orchestrates fallback on failure.
All backends are tried in order; if all fail, the registry returns a
fail-closed result (PROMPT_INJECTION_ONLY, confidence=1.0).

Thread-safe: swap() uses a lock so live config changes are atomic.

YSG-RISK-257 (circuit breaker): a backend that has just failed
``_BREAKER_FAILURE_THRESHOLD`` times in a row is short-circuited — skipped
without attempting another blocking network call — for
``_BREAKER_COOLDOWN_SECONDS``. This bounds worst-case per-request latency
during a sustained backend outage (every request would otherwise re-pay the
full connect/read timeout for a backend already known to be down) and stops
the thread pool that now runs these blocking calls (see
gateway/proxy.py, gateway/openai_router.py, gateway/agent_router.py,
gateway/mcp_router_runtime.py, gateway/orchestrator.py — all offload via
asyncio.to_thread) from filling up with doomed attempts.

Last updated: 2026-07-28
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from yashigani.inspection.backend_base import (
    ClassifierBackend,
    ClassifierResult,
    BackendUnavailableError,
)

logger = logging.getLogger(__name__)

_FAIL_CLOSED_RESULT = ClassifierResult(
    label="PROMPT_INJECTION_ONLY",
    confidence=1.0,
    backend="fail_closed",
    latency_ms=0,
)

# YSG-RISK-257 circuit-breaker tuning. Consecutive-failure count that opens
# the circuit, and how long it stays open before a single half-open trial
# attempt is allowed through.
_BREAKER_FAILURE_THRESHOLD = 3
_BREAKER_COOLDOWN_SECONDS = 30.0


class BackendRegistry:
    """
    Maintains an ordered fallback chain of classifier backends.

    fallback_chain: ordered list of backend names to try after the active
    backend fails. Use the sentinel string "fail_closed" as the last entry
    to explicitly mark the end of the chain (it is always implied).

    all_backends: dict mapping backend name -> ClassifierBackend instance.
    The active backend must be in all_backends.
    """

    def __init__(
        self,
        active_backend: ClassifierBackend,
        fallback_chain: list[str],
        all_backends: dict[str, ClassifierBackend],
        audit_writer=None,
    ) -> None:
        self._active_backend = active_backend
        self._fallback_chain = list(fallback_chain)
        self._all_backends = dict(all_backends)
        self._audit = audit_writer
        self._lock = threading.Lock()

        # YSG-RISK-257 circuit breaker state, keyed by backend name.
        self._breaker_lock = threading.Lock()
        self._breaker_failures: dict[str, int] = {}
        self._breaker_opened_at: dict[str, float] = {}

    # ── Classification ────────────────────────────────────────────────────────

    def classify(self, content: str, request_id: str = "") -> ClassifierResult:
        """
        Classify content using the active backend, falling back through the
        chain on BackendUnavailableError.

        If all backends are exhausted, returns _FAIL_CLOSED_RESULT and emits
        an InspectionBackendFallbackExhaustedEvent.
        """
        with self._lock:
            active = self._active_backend
            chain = list(self._fallback_chain)

        backends_tried: list[str] = []

        # Try active backend first
        result = self._try_backend(active, content, request_id, backends_tried, position=None)
        if result is not None:
            self._emit_metric_success(active.name, result)
            return result

        # Walk fallback chain
        for position, name in enumerate(chain):
            if name == "fail_closed":
                break

            with self._lock:
                backend = self._all_backends.get(name)

            if backend is None:
                logger.warning(
                    "BackendRegistry: fallback backend %r not found in all_backends "
                    "(request_id=%s)",
                    name, request_id,
                )
                backends_tried.append(name)
                continue

            # Emit fallback event
            self._emit_fallback_event(
                failed_backend=backends_tried[-1] if backends_tried else active.name,
                next_backend=name,
                position=position,
                request_id=request_id,
            )
            self._emit_metric_fallback(
                failed=backends_tried[-1] if backends_tried else active.name,
                next_b=name,
            )

            result = self._try_backend(backend, content, request_id, backends_tried, position)
            if result is not None:
                self._emit_metric_success(name, result)
                return result

        # All backends exhausted — fail-closed
        self._emit_exhausted_event(backends_tried, request_id)
        self._emit_metric_exhausted()
        return _FAIL_CLOSED_RESULT

    # ── Configuration ─────────────────────────────────────────────────────────

    def swap(
        self,
        new_active_backend: ClassifierBackend,
        new_fallback_chain: list[str],
    ) -> None:
        """Thread-safe swap of the active backend and fallback chain."""
        with self._lock:
            self._active_backend = new_active_backend
            self._fallback_chain = list(new_fallback_chain)
        logger.info(
            "BackendRegistry: swapped active backend to %s, chain=%s",
            new_active_backend.name, new_fallback_chain,
        )

    def get_active_backend_name(self) -> str:
        with self._lock:
            return self._active_backend.name

    def get_fallback_chain(self) -> list[str]:
        with self._lock:
            return list(self._fallback_chain)

    def health_status(self) -> dict[str, bool]:
        """Return {backend_name: health_check_result} for all registered backends."""
        with self._lock:
            backends = dict(self._all_backends)
        return {name: _safe_health_check(b) for name, b in backends.items()}

    # ── Internal ─────────────────────────────────────────────────────────────

    def _circuit_is_open(self, name: str) -> bool:
        """YSG-RISK-257: True if *name*'s circuit is open and still cooling down.

        A cooled-down circuit (elapsed >= _BREAKER_COOLDOWN_SECONDS since it
        opened) returns False here so exactly one half-open trial attempt is
        let through; success closes the circuit, failure re-opens it.
        """
        with self._breaker_lock:
            opened_at = self._breaker_opened_at.get(name)
            if opened_at is None:
                return False
            return time.monotonic() - opened_at < _BREAKER_COOLDOWN_SECONDS

    def _record_breaker_success(self, name: str) -> None:
        with self._breaker_lock:
            self._breaker_failures.pop(name, None)
            self._breaker_opened_at.pop(name, None)

    def _record_breaker_failure(self, name: str) -> None:
        with self._breaker_lock:
            failures = self._breaker_failures.get(name, 0) + 1
            self._breaker_failures[name] = failures
            if failures >= _BREAKER_FAILURE_THRESHOLD:
                self._breaker_opened_at[name] = time.monotonic()

    def _try_backend(
        self,
        backend: ClassifierBackend,
        content: str,
        request_id: str,
        backends_tried: list[str],
        position,
    ) -> Optional[ClassifierResult]:
        """
        Attempt classification on a single backend.
        Returns ClassifierResult on success, None on BackendUnavailableError
        or when the backend's circuit is open (YSG-RISK-257).
        Appends backend name to backends_tried regardless of outcome.
        """
        backends_tried.append(backend.name)

        # YSG-RISK-257: skip the blocking network call entirely for a backend
        # that has just failed repeatedly — every request during an outage
        # would otherwise re-pay the full connect/read timeout sequentially.
        if self._circuit_is_open(backend.name):
            logger.warning(
                "BackendRegistry: backend %r circuit OPEN — skipping attempt "
                "without a network call (request_id=%s)",
                backend.name, request_id,
            )
            self._emit_unreachable_event(
                backend.name,
                BackendUnavailableError("circuit_open (breaker cooldown)"),
                request_id,
            )
            self._emit_metric_failure(backend.name)
            return None

        start = int(time.monotonic() * 1000)
        try:
            result = backend.classify(content)
            self._record_breaker_success(backend.name)
            return result
        except BackendUnavailableError as exc:
            elapsed = int(time.monotonic() * 1000) - start
            logger.warning(
                "BackendRegistry: backend %r unavailable (request_id=%s, elapsed=%dms): %s",
                backend.name, request_id, elapsed, exc,
            )
            self._record_breaker_failure(backend.name)
            self._emit_unreachable_event(backend.name, exc, request_id)
            self._emit_metric_failure(backend.name)
            return None

    def _emit_unreachable_event(
        self, backend_name: str, exc: Exception, request_id: str
    ) -> None:
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import InspectionBackendUnreachableEvent
            self._audit.write(InspectionBackendUnreachableEvent(
                backend_name=backend_name,
                error_type=type(exc).__name__,
                error_message=type(exc).__name__,
                request_id=request_id,
            ))
        except Exception as e:
            logger.debug("BackendRegistry: failed to emit unreachable event: %s", e)

    def _emit_fallback_event(
        self,
        failed_backend: str,
        next_backend: str,
        position: int,
        request_id: str,
    ) -> None:
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import InspectionBackendFallbackEvent
            self._audit.write(InspectionBackendFallbackEvent(
                failed_backend=failed_backend,
                next_backend=next_backend,
                fallback_position=position,
                request_id=request_id,
            ))
        except Exception as e:
            logger.debug("BackendRegistry: failed to emit fallback event: %s", e)

    def _emit_exhausted_event(
        self, backends_tried: list[str], request_id: str
    ) -> None:
        logger.error(
            "BackendRegistry: all backends exhausted — fail-closed "
            "(request_id=%s, tried=%s)",
            request_id, backends_tried,
        )
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import InspectionBackendFallbackExhaustedEvent
            self._audit.write(InspectionBackendFallbackExhaustedEvent(
                backends_tried=backends_tried,
                request_id=request_id,
                action_taken="PROMPT_INJECTION_ONLY",
            ))
        except Exception as e:
            logger.debug("BackendRegistry: failed to emit exhausted event: %s", e)

    # ── Prometheus helpers ────────────────────────────────────────────────────

    def _emit_metric_success(self, backend_name: str, result: ClassifierResult) -> None:
        try:
            from yashigani.metrics.registry import (
                inspection_backend_requests_total,
                inspection_backend_latency_seconds,
            )
            inspection_backend_requests_total.labels(
                backend=backend_name, outcome="success"
            ).inc()
            inspection_backend_latency_seconds.labels(
                backend=backend_name
            ).observe(result.latency_ms / 1000)
        except Exception:
            pass

    def _emit_metric_failure(self, backend_name: str) -> None:
        try:
            from yashigani.metrics.registry import inspection_backend_requests_total
            inspection_backend_requests_total.labels(
                backend=backend_name, outcome="failure"
            ).inc()
        except Exception:
            pass

    def _emit_metric_fallback(self, failed: str, next_b: str) -> None:
        try:
            from yashigani.metrics.registry import inspection_backend_fallbacks_total
            inspection_backend_fallbacks_total.labels(
                failed_backend=failed, next_backend=next_b
            ).inc()
        except Exception:
            pass

    def _emit_metric_exhausted(self) -> None:
        try:
            from yashigani.metrics.registry import inspection_backend_exhausted_total
            inspection_backend_exhausted_total.inc()
        except Exception:
            pass


def _safe_health_check(backend: ClassifierBackend) -> bool:
    try:
        return backend.health_check()
    except Exception:
        return False
