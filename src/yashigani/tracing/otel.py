"""
OpenTelemetry tracing setup — Phase 9.

Initialises the OTLP gRPC exporter pointing at the otel-collector.
W3C traceparent propagated inbound and outbound.
X-Trace-Id response header set from the active span's trace ID.

env:
  OTEL_EXPORTER_OTLP_ENDPOINT       — default: http://otel-collector:4317
  YASHIGANI_ENVIRONMENT_LABEL       — sets deployment.environment resource attribute
                                      (LIC-001: YASHIGANI_ENV is reserved for license
                                      enforcement only; use this var for telemetry labels)
"""
from __future__ import annotations

import logging
import os

import yashigani

logger = logging.getLogger(__name__)

_tracer = None
_tracer_provider = None


def _span_processor_base():
    """Return opentelemetry.sdk.trace.SpanProcessor if available, else object.

    Using a function avoids a module-level import failure when the OTel SDK is
    not installed (the class definition would still succeed in that case, but
    the SDK won't call _on_ending on it either — so the fallback to ``object``
    is safe).
    """
    try:
        from opentelemetry.sdk.trace import SpanProcessor  # type: ignore[attr-defined]
        return SpanProcessor
    except Exception:
        return object


class _PrometheusSpanProcessor(_span_processor_base()):  # type: ignore[misc]
    """Lightweight span processor that increments yashigani_trace_spans_total
    on every span that ends.  Runs synchronously in on_end() — single counter
    increment only; never blocks the export pipeline.

    Inherits from ``opentelemetry.sdk.trace.SpanProcessor`` so that the SDK's
    ``SynchronousMultiSpanProcessor`` can call ``_on_ending`` (added in OTel
    SDK ≥ 1.26) without raising ``AttributeError``.  The base class provides
    ``_on_ending`` as a no-op; we do not need to override it because the span
    counter is emitted in ``on_end``, which fires after ``_on_ending``.

    status_code → status label mapping:
      STATUS_CODE_OK        → "ok"
      STATUS_CODE_ERROR     → "error"
      STATUS_CODE_UNSET     → "unset"
    """

    def on_start(self, span, parent_context=None) -> None:  # noqa: D102
        pass

    def on_end(self, span) -> None:  # noqa: D102
        try:
            from yashigani.metrics.registry import trace_spans_total
            try:
                from opentelemetry.trace import StatusCode
                _code = getattr(span.status, "status_code", None)
                if _code == StatusCode.OK:
                    _status = "ok"
                elif _code == StatusCode.ERROR:
                    _status = "error"
                else:
                    _status = "unset"
            except Exception:
                _status = "unset"
            _name = getattr(span, "name", "unknown") or "unknown"
            trace_spans_total.labels(span_name=_name, status=_status).inc()
        except Exception:  # noqa: BLE001 — metric must never disrupt tracing
            pass

    def shutdown(self) -> None:  # noqa: D102
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:  # noqa: D102
        return True


def setup_tracer(service_name: str = "yashigani-gateway") -> None:
    """Call once at application startup."""
    global _tracer, _tracer_provider
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.propagate import set_global_textmap
        from opentelemetry.propagators.composite import CompositePropagator

        try:
            from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
        except ImportError:
            from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
        resource = Resource.create({
            "service.name": service_name,
            "service.version": yashigani.__version__,
            # LIC-001: Use YASHIGANI_ENVIRONMENT_LABEL for telemetry labels.
            # YASHIGANI_ENV is reserved for license enforcement (verifier.py)
            # and is hardcoded to "production" in deployed images — it must not
            # be used as a telemetry label because its value is non-configurable.
            "deployment.environment": os.getenv("YASHIGANI_ENVIRONMENT_LABEL", "production"),
        })
        provider = TracerProvider(resource=resource)
        otel_insecure = os.getenv("OTEL_EXPORTER_INSECURE", "false").lower() in ("true", "1", "yes")
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=otel_insecure)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        # Prometheus span counter — incremented for every span that ends.
        # Wires yashigani_trace_spans_total{span_name, status} used by the
        # Tracing Grafana dashboard.
        provider.add_span_processor(_PrometheusSpanProcessor())
        trace.set_tracer_provider(provider)
        set_global_textmap(CompositePropagator([TraceContextTextMapPropagator()]))
        _tracer_provider = provider
        _tracer = trace.get_tracer(service_name)
        logger.info("OpenTelemetry tracer configured: endpoint=%s", otlp_endpoint)
    except ImportError as exc:
        logger.warning("OpenTelemetry packages not installed — tracing disabled: %s", exc)
    except Exception as exc:
        logger.warning("OpenTelemetry setup failed — tracing disabled: %s", exc)


def get_tracer():
    """Return the active tracer, or a no-op tracer if OTEL is unavailable."""
    global _tracer
    if _tracer is None:
        try:
            from opentelemetry import trace
            _tracer = trace.get_tracer("yashigani")
        except Exception:
            return _NoOpTracer()
    return _tracer


def current_trace_id() -> str:
    """Return current W3C trace ID hex string, or empty string."""
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return ""


class _NoOpTracer:
    class _NoOpSpan:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def set_attribute(self, *args): pass
        def set_status(self, *args): pass
        def record_exception(self, *args): pass

    def start_as_current_span(self, name, **kwargs):
        return self._NoOpSpan()

    def start_span(self, name, **kwargs):
        return self._NoOpSpan()
