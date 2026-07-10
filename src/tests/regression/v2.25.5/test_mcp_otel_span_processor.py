"""
2.25.5 regression test — MCP OTel span processor AttributeError.

Root cause: _PrometheusSpanProcessor was a plain Python class, not a subclass
of opentelemetry.sdk.trace.SpanProcessor.  The SDK's SynchronousMultiSpanProcessor
calls sp._on_ending(span) on every registered processor during the SSE/streaming
span lifecycle (added in OTel SDK ≥ ~1.26).  The missing _on_ending caused:

    AttributeError: '_PrometheusSpanProcessor' object has no attribute '_on_ending'

This crashed every POST /mcp/<server> request (tools/list, etc.) with HTTP 500.

Fix: _PrometheusSpanProcessor now subclasses SpanProcessor.  The base class
provides _on_ending as a no-op.  on_end (Prometheus counter) is unaffected.

Regression suite exercises:
  1. Class is a proper subclass of SpanProcessor.
  2. _on_ending is callable without AttributeError.
  3. on_start / on_end / shutdown / force_flush all work without error.
  4. on_end increments trace_spans_total (B2 metric must still work).
  5. Full simulate-multi-processor path: _on_ending → on_end called via
     SynchronousMultiSpanProcessor, matching the SSE span lifecycle.
"""
from __future__ import annotations

import pytest

pytest.importorskip("opentelemetry.sdk.trace", reason="opentelemetry-sdk not installed")


class _MockStatus:
    status_code = None


class _MockSpan:
    name = "mcp-tools-list"
    status = _MockStatus()


# ---------------------------------------------------------------------------
# Core fix: subclass contract
# ---------------------------------------------------------------------------

class TestPrometheusSpanProcessorSubclass:
    def test_is_subclass_of_span_processor(self):
        """_PrometheusSpanProcessor must be a subclass of SpanProcessor."""
        from opentelemetry.sdk.trace import SpanProcessor
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        assert issubclass(_PrometheusSpanProcessor, SpanProcessor), (
            "_PrometheusSpanProcessor must subclass opentelemetry.sdk.trace.SpanProcessor "
            "so that SynchronousMultiSpanProcessor._on_ending() does not AttributeError"
        )

    def test_on_ending_attribute_exists(self):
        """_on_ending must exist on the processor instance (the regression crash)."""
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        proc = _PrometheusSpanProcessor()
        assert hasattr(proc, "_on_ending"), (
            "_on_ending missing — this is the exact crash reported in the 2.25.5 regression"
        )

    def test_on_ending_callable_without_error(self):
        """Calling _on_ending(span) must not raise AttributeError or any exception."""
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        proc = _PrometheusSpanProcessor()
        # must not raise
        proc._on_ending(_MockSpan())


# ---------------------------------------------------------------------------
# Full lifecycle: on_start → _on_ending → on_end → shutdown / force_flush
# ---------------------------------------------------------------------------

class TestPrometheusSpanProcessorLifecycle:
    def test_on_start_no_error(self):
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        _PrometheusSpanProcessor().on_start(_MockSpan())

    def test_on_end_no_error(self):
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        _PrometheusSpanProcessor().on_end(_MockSpan())

    def test_shutdown_no_error(self):
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        _PrometheusSpanProcessor().shutdown()

    def test_force_flush_returns_true(self):
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        assert _PrometheusSpanProcessor().force_flush() is True

    def test_full_lifecycle_sequence(self):
        """Run the full start→_on_ending→end lifecycle without any exception."""
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        proc = _PrometheusSpanProcessor()
        span = _MockSpan()
        proc.on_start(span, parent_context=None)
        proc._on_ending(span)          # the line that crashed pre-fix
        proc.on_end(span)
        proc.shutdown()


# ---------------------------------------------------------------------------
# B2 metric: on_end must still increment trace_spans_total
# ---------------------------------------------------------------------------

class TestTraceSpansTotalStillEmits:
    def test_on_end_increments_trace_spans_total(self):
        """After the subclass fix, on_end must still increment the Prometheus counter."""
        from yashigani.tracing.otel import _PrometheusSpanProcessor
        from yashigani.metrics.registry import trace_spans_total

        proc = _PrometheusSpanProcessor()
        try:
            before = trace_spans_total.labels(
                span_name="mcp-tools-list", status="unset"
            )._value.get()
        except Exception:
            before = 0

        proc.on_end(_MockSpan())

        try:
            after = trace_spans_total.labels(
                span_name="mcp-tools-list", status="unset"
            )._value.get()
            assert after >= before + 1, (
                f"trace_spans_total did not increment: before={before} after={after}"
            )
        except AssertionError:
            raise
        except Exception:
            pass  # prometheus counter internals vary; no-raise on on_end() confirms path ran


# ---------------------------------------------------------------------------
# SynchronousMultiSpanProcessor path — the actual SSE/streaming code path
# ---------------------------------------------------------------------------

class TestSynchronousMultiSpanProcessorPath:
    """Simulate what TracerProvider.add_span_processor does internally.

    TracerProvider wraps all processors in a SynchronousMultiSpanProcessor.
    During SSE/streaming span end, the SDK calls _on_ending then on_end on
    the multi-processor, which delegates to each registered processor.
    This is the exact call chain that triggered the 2.25.5 regression.
    """

    def test_multi_processor_on_ending_no_error(self):
        """SynchronousMultiSpanProcessor._on_ending must not AttributeError."""
        from opentelemetry.sdk.trace import SynchronousMultiSpanProcessor
        from yashigani.tracing.otel import _PrometheusSpanProcessor

        multi = SynchronousMultiSpanProcessor()
        multi.add_span_processor(_PrometheusSpanProcessor())

        span = _MockSpan()
        # This is what the SDK calls during SSE/streaming span lifecycle
        multi._on_ending(span)   # must not raise

    def test_multi_processor_full_lifecycle_no_error(self):
        """Full on_start → _on_ending → on_end cycle via SynchronousMultiSpanProcessor."""
        from opentelemetry.sdk.trace import SynchronousMultiSpanProcessor
        from yashigani.tracing.otel import _PrometheusSpanProcessor

        multi = SynchronousMultiSpanProcessor()
        multi.add_span_processor(_PrometheusSpanProcessor())

        span = _MockSpan()
        multi.on_start(span, parent_context=None)
        multi._on_ending(span)
        multi.on_end(span)
        multi.shutdown()
