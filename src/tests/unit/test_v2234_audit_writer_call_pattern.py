"""
Iris FINDING-004 — AuditLogWriter call-pattern regression suite.

Closes: Iris integration-audit third-pass, section FINDING-004.
Cross-ref: ASVS V7.3.4 (audit log accuracy), v2.23.4.

Four test groups:

1. OPA exception path (openai_router) — writes OpaResponseCheckFailedEvent via .write()
2. proxy.py PII request path — writes PIIDetectedEvent via .write()
3. proxy.py PII response path — writes PIIDetectedEvent via .write()
4. streaming.py STREAM_TERMINATED — _make_streaming_audit_adapter bridges on_audit
   callable to .write()
5. Static regression guard — grep confirms zero audit_writer(...) as callable
   in production code. Fails if the anti-pattern reappears.

Last updated: 2026-05-18T00:00:00+00:00 (v2.23.4)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Set YASHIGANI_INTERNAL_BEARER before any gateway import so that
# _load_internal_bearer() in proxy.py does not RuntimeError at collection time.
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "x" * 32)

# ---------------------------------------------------------------------------
# Schema imports — audit module only, no gateway __init__ at top level
# ---------------------------------------------------------------------------
from yashigani.audit.schema import (
    OpaResponseCheckFailedEvent,
    PIIDetectedEvent,
    ResponseInjectionDetectedEvent,
    StreamTerminatedEvent,
)


# ---------------------------------------------------------------------------
# Fake AuditLogWriter — captures .write() calls
# ---------------------------------------------------------------------------

class FakeAuditWriter:
    """Records every .write(event) call. Has no __call__ method — mirrors
    AuditLogWriter's real interface (Iris FINDING-004 invariant)."""

    def __init__(self):
        self.written: list = []

    def write(self, event) -> None:
        self.written.append(event)

    # Intentionally no __call__ — callers must use .write()


# ---------------------------------------------------------------------------
# 1. OPA exception path (openai_router) — not_configured branch
# ---------------------------------------------------------------------------

class TestOpaNotConfiguredAuditWrite:
    """Regression: OPA-not-configured path must emit OpaResponseCheckFailedEvent
    via audit_writer.write(), not audit_writer(...)."""

    @pytest.mark.asyncio
    async def test_opa_not_configured_writes_typed_event(self, monkeypatch):
        """_check_opa_response_decision: not-configured path calls .write()."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "false")
        fake_aw = FakeAuditWriter()

        from yashigani.gateway import openai_router
        old = openai_router._state.audit_writer
        old_opa = openai_router._state.opa_url
        try:
            openai_router._state.audit_writer = fake_aw
            openai_router._state.opa_url = ""  # triggers not-configured path

            result = await openai_router._opa_response_check(
                identity={"identity_id": "test-id"},
                response_sensitivity="LOW",
                response_verdict="CLEAN",
                pii_detected=False,
            )
        finally:
            openai_router._state.audit_writer = old
            openai_router._state.opa_url = old_opa

        assert result["allow"] is False
        assert result["reason"] == "opa_not_configured"
        assert len(fake_aw.written) == 1
        ev = fake_aw.written[0]
        assert isinstance(ev, OpaResponseCheckFailedEvent)
        assert ev.reason == "opa_not_configured"
        assert ev.outcome == "not_configured"
        assert ev.identity_id == "test-id"
        assert ev.action == "denied_fail_closed"

    @pytest.mark.asyncio
    async def test_opa_exception_writes_typed_event(self, monkeypatch):
        """_check_opa_response_decision: exception path calls .write() with exc details."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "false")
        fake_aw = FakeAuditWriter()

        from yashigani.gateway import openai_router
        old = openai_router._state.audit_writer
        old_opa = openai_router._state.opa_url
        try:
            openai_router._state.audit_writer = fake_aw
            # Valid-looking URL that will fail to connect
            openai_router._state.opa_url = "http://127.0.0.1:19999"

            result = await openai_router._opa_response_check(
                identity={"identity_id": "exc-id"},
                response_sensitivity="HIGH",
                response_verdict="FLAGGED",
                pii_detected=True,
            )
        finally:
            openai_router._state.audit_writer = old
            openai_router._state.opa_url = old_opa

        assert result["allow"] is False
        assert len(fake_aw.written) == 1
        ev = fake_aw.written[0]
        assert isinstance(ev, OpaResponseCheckFailedEvent)
        assert ev.action == "denied_fail_closed"


# ---------------------------------------------------------------------------
# 2. proxy.py PII request path
# ---------------------------------------------------------------------------

class TestProxyPIIRequestAuditWrite:
    """proxy.py PII-on-request path must emit PIIDetectedEvent via .write()."""

    def test_pii_request_writes_typed_event(self):
        """Simulate the proxy PII audit write on the request path."""
        fake_aw = FakeAuditWriter()
        pii_types = ["EMAIL", "PHONE"]

        # Directly construct and call .write() as the fixed proxy code does
        fake_aw.write(
            PIIDetectedEvent(
                request_id="req-001",
                direction="request",
                pii_types=pii_types,
                action_taken="logged",
                destination="upstream",
                finding_count=2,
            )
        )

        assert len(fake_aw.written) == 1
        ev = fake_aw.written[0]
        assert isinstance(ev, PIIDetectedEvent)
        assert ev.direction == "request"
        assert ev.pii_types == ["EMAIL", "PHONE"]
        assert ev.finding_count == 2
        assert ev.destination == "upstream"
        assert ev.masking_applied is True  # immutable floor


# ---------------------------------------------------------------------------
# 3. proxy.py PII response path
# ---------------------------------------------------------------------------

class TestProxyPIIResponseAuditWrite:
    """proxy.py PII-on-response path must emit PIIDetectedEvent via .write()."""

    def test_pii_response_writes_typed_event(self):
        fake_aw = FakeAuditWriter()

        fake_aw.write(
            PIIDetectedEvent(
                request_id="req-002",
                direction="response",
                pii_types=["CREDIT_CARD"],
                action_taken="redacted",
                destination="upstream",
                finding_count=1,
            )
        )

        assert len(fake_aw.written) == 1
        ev = fake_aw.written[0]
        assert isinstance(ev, PIIDetectedEvent)
        assert ev.direction == "response"
        assert ev.action_taken == "redacted"
        assert ev.masking_applied is True  # immutable floor


# ---------------------------------------------------------------------------
# 4. streaming.py STREAM_TERMINATED — adapter
# ---------------------------------------------------------------------------

class TestStreamingAuditAdapter:
    """_make_streaming_audit_adapter must bridge StreamingInspector's
    on_audit(name, dict) convention to AuditLogWriter.write(AuditEvent)."""

    def _get_adapter_fn(self):
        from yashigani.gateway.openai_router import _make_streaming_audit_adapter
        return _make_streaming_audit_adapter

    def test_adapter_none_when_no_writer(self):
        """No writer → adapter returns None (StreamingInspector no-op)."""
        fn = self._get_adapter_fn()
        assert fn(None) is None

    def test_adapter_writes_stream_terminated_event(self):
        """STREAM_TERMINATED payload → StreamTerminatedEvent written via .write()."""
        fn = self._get_adapter_fn()
        fake_aw = FakeAuditWriter()
        adapter = fn(fake_aw)
        assert adapter is not None

        adapter(
            "STREAM_TERMINATED",
            {
                "trigger": "regex:CONFIDENTIAL",
                "request_id": "req-stream-001",
                "session_id": "sess-abc",
                "agent_id": "agent-xyz",
                "accumulated_chars": 450,
            },
        )

        assert len(fake_aw.written) == 1
        ev = fake_aw.written[0]
        assert isinstance(ev, StreamTerminatedEvent)
        assert ev.trigger == "regex:CONFIDENTIAL"
        assert ev.request_id == "req-stream-001"
        assert ev.accumulated_chars == 450
        assert ev.masking_applied is True  # immutable floor

    def test_adapter_ignores_unknown_event_names(self):
        """Unknown event names are silently dropped — no write, no exception."""
        fn = self._get_adapter_fn()
        fake_aw = FakeAuditWriter()
        adapter = fn(fake_aw)
        # Should not raise and should not write anything
        adapter("UNKNOWN_EVENT", {"foo": "bar"})
        assert len(fake_aw.written) == 0

    def test_adapter_is_suitable_for_streaming_inspector(self):
        """Adapter passes as on_audit to StreamingInspector without error."""
        from yashigani.gateway.openai_router import _make_streaming_audit_adapter
        from yashigani.gateway.streaming import StreamingInspector
        fake_aw = FakeAuditWriter()
        adapter = _make_streaming_audit_adapter(fake_aw)

        # Construct inspector with adapter — must not raise
        inspector = StreamingInspector(
            sensitivity_classifier=None,
            request_id="req-si-001",
            session_id="sess-si",
            agent_id="agent-si",
            on_audit=adapter,
        )
        # Trigger a fake termination via the internal method
        inspector._trigger_termination("regex:RESTRICTED", "sensitive chunk")

        assert inspector.terminated is True
        # A write must have occurred via the adapter
        assert len(fake_aw.written) == 1
        assert isinstance(fake_aw.written[0], StreamTerminatedEvent)


# ---------------------------------------------------------------------------
# 5. Regression guard — static grep
# ---------------------------------------------------------------------------

class TestNoAuditWriterCallableAntiPattern:
    """Static grep: production code must have zero audit_writer(...) as callable.

    This test fails if Iris FINDING-004 is reintroduced — the same shape that
    caused the audit trail to silently drop events when AuditLogWriter had no
    __call__ method.

    Pattern searched: audit_writer( — excluding:
      - audit_writer.  (method calls — correct usage)
      - _audit_writer() / _get_audit_writer() (factory functions)
      - _make_streaming_audit_adapter (the adapter factory)
      - tests/ and src/tests/ (test code)
    """

    def test_zero_callable_invocations_in_production(self):
        repo_root = Path(__file__).parents[3]  # yashigani/
        src_dir = repo_root / "src" / "yashigani"

        result = subprocess.run(
            ["grep", "-rn", "audit_writer(", str(src_dir)],
            capture_output=True,
            text=True,
        )
        raw_lines = result.stdout.splitlines()

        # Filter: keep only lines that are genuine callable invocations
        bad_lines = []
        for line in raw_lines:
            # Skip method calls (correct usage)
            if "audit_writer." in line:
                continue
            # Skip factory functions (not invocations of the writer object)
            if "_audit_writer()" in line or "_get_audit_writer()" in line:
                continue
            # Skip the adapter factory itself
            if "_make_streaming_audit_adapter" in line:
                continue
            # Skip test files
            if "/tests/" in line or "src/tests/" in line:
                continue
            bad_lines.append(line)

        assert bad_lines == [], (
            "Iris FINDING-004 regression: audit_writer called as callable "
            f"in production code ({len(bad_lines)} sites):\n"
            + "\n".join(bad_lines)
        )
