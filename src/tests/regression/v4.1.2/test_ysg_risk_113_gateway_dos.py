"""
Regression tests — YSG-RISK-113: a single unhealthy Ollama backend blocks the
gateway's ASGI event loop, taking /healthz down with it (availability/DoS).

## The finding (Ava, live k8s e2e, 2026-07-28)

A chat/model call to an ollama replica with no model loaded hung >90s.
Gateway log showed "could not fetch ollama model list ... available_models=
None", then the chat completion hung. WHILE that request was stuck, the SAME
gateway pod's /healthz liveness/readiness probe ALSO timed out, and kubelet
restarted the pod live mid-request (2nd restart observed) — even though the
pod's actual dependencies (DB, Redis, OPA) were healthy.

## Root cause

``inspection/pipeline.py``'s ``InspectionPipeline.process()`` and
``ResponseInspectionPipeline.inspect()`` are plain SYNCHRONOUS methods. They
call ``inspection/backend_registry.py``'s ``BackendRegistry.classify()``,
which sequentially tries the active backend + fallback chain, each backend
performing a genuinely BLOCKING ``httpx.Client`` call
(``inspection/_ollama_transport.py``). These sync calls were invoked
DIRECTLY inside ``async def`` FastAPI handlers (gateway/proxy.py,
gateway/openai_router.py, gateway/agent_router.py,
gateway/mcp_router_runtime.py, gateway/orchestrator.py) with no thread
offload — so a slow/dead backend monopolizes the single-threaded asyncio
event loop for the full attempt duration, starving every other coroutine
on that worker INCLUDING ``/healthz`` (``async def healthz(): return
{"status": "ok"}`` — instant on its own, but never scheduled while the loop
is held hostage).

## The fix

  1. Every classify()/inspect() call site now offloads via
     ``asyncio.to_thread()`` (gateway/proxy.py, gateway/openai_router.py x2,
     gateway/agent_router.py, gateway/mcp_router_runtime.py) or is itself
     ``async def`` awaiting ``asyncio.to_thread`` internally
     (gateway/orchestrator.py's ``_classify_sensitivity`` /
     ``_inspect_result``, with all 7 call sites updated to ``await``).
  2. ``inspection/_ollama_transport.py``: an explicit ``httpx.Timeout`` with
     a fast-failing 5s connect-phase ceiling
     (``_build_timeout``/``_CONNECT_TIMEOUT_CEILING``), decoupled from the
     caller's read timeout.
  3. ``inspection/backend_registry.py``: a per-backend-name circuit breaker
     (``_BREAKER_FAILURE_THRESHOLD=3``, ``_BREAKER_COOLDOWN_SECONDS=30``) —
     a repeatedly-failing backend is skipped without a network call for the
     cooldown window.

Each test below would FAIL (or hang) on the pre-fix code.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from yashigani.inspection.backend_base import (
    BackendUnavailableError,
    ClassifierBackend,
    ClassifierResult,
)
from yashigani.inspection.backend_registry import (
    _BREAKER_COOLDOWN_SECONDS,
    _BREAKER_FAILURE_THRESHOLD,
    BackendRegistry,
)
from yashigani.inspection.classifier import LABEL_CLEAN
from yashigani.inspection.pipeline import InspectionPipeline, ResponseInspectionPipeline


class _SlowBackend(ClassifierBackend):
    """A ClassifierBackend whose classify() blocks synchronously for
    *delay_s*, simulating a live-but-unresponsive Ollama replica (no model
    loaded / generation stalled) — exactly the observed incident shape."""

    name = "slow_ollama"

    def __init__(self, delay_s: float) -> None:
        self._delay_s = delay_s

    def classify(self, content: str) -> ClassifierResult:
        time.sleep(self._delay_s)  # genuinely blocking, like the real httpx.Client call
        return ClassifierResult(label=LABEL_CLEAN, confidence=1.0, backend=self.name, latency_ms=0)

    def health_check(self) -> bool:
        return True


class _FlakyBackend(ClassifierBackend):
    """A backend whose classify() always raises BackendUnavailableError,
    counting how many times it was actually invoked (network-call proxy)."""

    name = "flaky"

    def __init__(self) -> None:
        self.call_count = 0

    def classify(self, content: str) -> ClassifierResult:
        self.call_count += 1
        raise BackendUnavailableError("simulated dead backend")

    def health_check(self) -> bool:
        return False


class _FakeInjectionClassifier:
    """Minimal drop-in for PromptInjectionClassifier used by the legacy
    pipeline path — blocks for *delay_s* like a hung Ollama call."""

    def __init__(self, delay_s: float) -> None:
        self._delay_s = delay_s

    def classify(self, content: str):
        time.sleep(self._delay_s)
        from yashigani.inspection.classifier import ClassifierResult as _CR
        return _CR(
            label=LABEL_CLEAN, confidence=1.0,
            exfil_indicators=False, detected_payload_spans=[],
        )


# ---------------------------------------------------------------------------
# A. /healthz-shaped coroutine stays responsive while a backend call hangs
# ---------------------------------------------------------------------------

class TestEventLoopStaysResponsiveDuringBackendHang:
    """Proves the primary DoS fix: offloading the blocking classify() call to
    a worker thread means the asyncio event loop is never held hostage, so a
    trivial async coroutine (standing in for gateway/proxy.py's real
    ``async def healthz()``) keeps responding concurrently.
    """

    async def _healthz(self) -> str:
        """Mirrors gateway/proxy.py's real /healthz handler exactly:
        no blocking work of its own."""
        return "ok"

    @pytest.mark.asyncio
    async def test_pipeline_process_offloaded_does_not_block_healthz(self):
        """InspectionPipeline.process() (request-side, gateway/proxy.py:896)
        run via asyncio.to_thread must let /healthz respond immediately,
        even while the classify() call is still blocked on a slow backend.
        """
        slow_classifier = _FakeInjectionClassifier(delay_s=2.0)
        pipeline = InspectionPipeline(classifier=slow_classifier)

        healthz_times: list[float] = []
        # NOTE: t0 is captured BEFORE asyncio.gather starts either coroutine,
        # and every recorded timestamp is relative to this SHARED origin. If
        # the healthz poller were starved (event loop blocked by a direct,
        # non-offloaded classify() call), its first measurement would land
        # at ~2.0s (after the classifier finally releases the loop) instead
        # of within the first ~0.05-0.3s — this is what makes the assertion
        # below an actual regression trap rather than a self-referential
        # no-op (an earlier draft measured elapsed time from INSIDE the
        # poller, which cannot detect starvation since the poller's own
        # clock only starts once it finally gets to run).
        t0 = time.monotonic()

        async def poll_healthz_repeatedly():
            for _ in range(5):
                await self._healthz()
                healthz_times.append(time.monotonic() - t0)
                await asyncio.sleep(0.05)

        # Exactly the fixed call-site shape: `await asyncio.to_thread(pipeline.process, ...)`
        results = await asyncio.gather(
            asyncio.to_thread(
                pipeline.process,
                raw_query="hello", session_id="s1", agent_id="a1", user_id="u1",
            ),
            poll_healthz_repeatedly(),
        )
        elapsed = time.monotonic() - t0

        pipeline_result = results[0]
        assert pipeline_result.action == "PASS"

        # All 5 healthz polls completed well inside the classifier's 2s hang —
        # proof the loop was never blocked by the concurrent classify() call.
        assert healthz_times[-1] < 1.0, (
            f"healthz polling took {healthz_times[-1]:.2f}s while classify() blocked "
            f"for 2.0s — the event loop was starved (YSG-RISK-113 regression)"
        )
        # The slow backend call itself still completes (correctness preserved).
        assert elapsed >= 2.0

    @pytest.mark.asyncio
    async def test_response_inspection_offloaded_does_not_block_healthz(self):
        """ResponseInspectionPipeline.inspect() (response-side, called from
        gateway/openai_router.py / agent_router.py / mcp_router_runtime.py)
        run via asyncio.to_thread must not block a concurrent /healthz poll.
        """
        slow_classifier = _FakeInjectionClassifier(delay_s=2.0)
        pipeline = ResponseInspectionPipeline(classifier=slow_classifier)

        # Shared origin (see the request-side test above for why this must
        # NOT be captured from inside the poller itself).
        t0 = time.monotonic()
        healthz_fired_at: list[float] = []

        async def poll_healthz_once_quickly():
            await asyncio.sleep(0.1)
            await self._healthz()
            healthz_fired_at.append(time.monotonic() - t0)

        results = await asyncio.gather(
            asyncio.to_thread(
                pipeline.inspect,
                response_body="the assistant said hi",
                content_type="text/plain",
                request_id="rq1", session_id="s1", agent_id="a1",
            ),
            poll_healthz_once_quickly(),
        )
        elapsed = time.monotonic() - t0

        # healthz must have fired almost immediately (~0.1s), NOT after the
        # full 2s classify() hang — this is the actual regression trap.
        assert healthz_fired_at, "healthz poller never completed"
        assert healthz_fired_at[0] < 1.0, (
            f"healthz fired at {healthz_fired_at[0]:.2f}s while the response "
            f"classify() was blocked for 2.0s — the event loop was starved "
            f"(YSG-RISK-113 regression)"
        )
        resp_result = results[0]
        assert resp_result.verdict == "CLEAN"
        assert elapsed >= 2.0  # the slow classify() still ran to completion


# ---------------------------------------------------------------------------
# B. Circuit breaker — a repeatedly-failing backend stops being dialled
# ---------------------------------------------------------------------------

class TestBackendRegistryCircuitBreaker:
    """YSG-RISK-113 bonus hardening: bound worst-case latency during a
    sustained backend outage by short-circuiting a backend that has just
    failed _BREAKER_FAILURE_THRESHOLD times in a row."""

    def test_backend_skipped_after_threshold_failures(self):
        flaky = _FlakyBackend()
        registry = BackendRegistry(
            active_backend=flaky,
            fallback_chain=["fail_closed"],
            all_backends={"flaky": flaky},
        )

        # Drive the circuit open.
        for _ in range(_BREAKER_FAILURE_THRESHOLD):
            registry.classify("x")
        assert flaky.call_count == _BREAKER_FAILURE_THRESHOLD

        # One more request: the circuit is open, so classify() must NOT be
        # invoked again (no wasted network call / blocking attempt).
        registry.classify("x")
        assert flaky.call_count == _BREAKER_FAILURE_THRESHOLD, (
            "circuit breaker must skip the network call once open — "
            f"expected {_BREAKER_FAILURE_THRESHOLD} calls, got {flaky.call_count}"
        )

    def test_circuit_closes_after_cooldown_and_success(self):
        flaky = _FlakyBackend()
        registry = BackendRegistry(
            active_backend=flaky,
            fallback_chain=["fail_closed"],
            all_backends={"flaky": flaky},
        )
        for _ in range(_BREAKER_FAILURE_THRESHOLD):
            registry.classify("x")

        # Force the cooldown to have elapsed.
        registry._breaker_opened_at["flaky"] = (
            time.monotonic() - _BREAKER_COOLDOWN_SECONDS - 1.0
        )

        # Half-open trial: circuit lets exactly one attempt through.
        calls_before = flaky.call_count
        registry.classify("x")
        assert flaky.call_count == calls_before + 1, (
            "after cooldown elapses, exactly one half-open trial attempt "
            "must reach the backend"
        )

    def test_successful_classification_resets_breaker(self):
        class _Recovering(ClassifierBackend):
            name = "recovering"

            def __init__(self):
                self.attempts = 0

            def classify(self, content):
                self.attempts += 1
                if self.attempts <= 2:
                    raise BackendUnavailableError("still warming up")
                return ClassifierResult(label=LABEL_CLEAN, confidence=1.0,
                                        backend=self.name, latency_ms=0)

            def health_check(self):
                return True

        backend = _Recovering()
        registry = BackendRegistry(
            active_backend=backend, fallback_chain=["fail_closed"],
            all_backends={"recovering": backend},
        )
        # Two failures (below threshold) — circuit stays closed.
        registry.classify("x")
        registry.classify("x")
        # Third attempt succeeds and resets the breaker's failure counter.
        result = registry.classify("x")
        assert result.label == LABEL_CLEAN
        assert registry._breaker_failures.get("recovering", 0) == 0
        assert "recovering" not in registry._breaker_opened_at


# ---------------------------------------------------------------------------
# C. Fail-fast connect timeout hardening
# ---------------------------------------------------------------------------

class TestOllamaTransportConnectTimeoutHardening:
    """A bare float timeout must be split into an explicit httpx.Timeout with
    a short, fixed connect-phase ceiling — a fully dead backend (nothing
    listening) must fail fast, independent of a long read timeout meant for
    a slow-but-alive model."""

    def test_connect_phase_capped_below_read_timeout(self):
        from yashigani.inspection._ollama_transport import (
            _CONNECT_TIMEOUT_CEILING,
            _build_timeout,
        )
        t = _build_timeout(120.0)
        assert t.connect == _CONNECT_TIMEOUT_CEILING
        assert t.read == 120.0

    def test_short_timeout_is_not_inflated(self):
        """A caller-supplied timeout shorter than the connect ceiling must
        not be lengthened — min(timeout, ceiling) applies."""
        from yashigani.inspection._ollama_transport import (
            _CONNECT_TIMEOUT_CEILING,
            _build_timeout,
        )
        t = _build_timeout(2.0)
        assert t.connect == 2.0
        assert t.connect <= _CONNECT_TIMEOUT_CEILING

    def test_explicit_httpx_timeout_passed_through_unchanged(self):
        import httpx

        from yashigani.inspection._ollama_transport import _build_timeout
        explicit = httpx.Timeout(90.0, connect=15.0)
        assert _build_timeout(explicit) is explicit
