"""
YSG-RISK-153: KMS secret-rotation observability.

Prior state:
  - ``KSMRotationScheduler.on_event`` defaulted to a no-op lambda, and the
    scheduler was constructed in ``backoffice/entrypoint.py`` without
    ``on_event`` at all, so ``KSM_ROTATION_SUCCESS/FAILURE/CRITICAL`` audit
    events never reached the audit trail.
  - The documented wiring example (``on_event=audit_logger.write``) would
    have raised ``AttributeError`` in production: ``KSMRotationScheduler``
    calls ``on_event(name, data)`` with a ``(str, dict)`` pair, but
    ``AuditLogWriter.write()`` takes a single ``AuditEvent`` instance.
  - ``yashigani_kms_rotations_total`` / ``kms_rotation_last_success_timestamp``
    had no emitter anywhere in the codebase, despite two live Prometheus
    alerts on the counter and a staleness alert on the gauge.

Fix under test: ``backoffice.entrypoint._make_ksm_rotation_event_handler``
adapts the scheduler's ``(name, data)`` callback into a real
``KsmRotationEvent`` audit write plus the two metric emitters, and is now
wired into the ``KSMRotationScheduler(...)`` construction call.

Note: unlike most modules, ``backoffice/entrypoint.py`` runs ``_bootstrap()``
at import time (requires ``/run/secrets`` etc.), so — matching the existing
convention in ``test_backoffice_break_glass_redis_timeout.py`` — this suite
does NOT import ``yashigani.backoffice.entrypoint``. Instead:
  - Group 1 uses AST inspection to verify the actual source wires the
    handler into the scheduler construction, and that the handler body
    performs the required audit-write + metric-emit calls.
  - Groups 2-3 replay the handler logic in isolation (a byte-for-byte
    functional copy of the fix) against the REAL ``KsmRotationEvent``,
    ``AuditLogWriter``, and metrics-registry counters/gauge, so the
    assertions are grounded in the real schema/metrics contracts even
    though the entrypoint module itself is never imported.

Test matrix:
  G1 — AST: on_event is wired at KSMRotationScheduler(...) construction;
       handler body references KsmRotationEvent / audit_writer.write /
       kms_rotations_total / kms_rotation_last_success_timestamp.
  T01 — success event: writes KsmRotationEvent (not a tuple), correct fields.
  T02 — success event: increments kms_rotations_total{outcome=success}.
  T03 — success event: sets kms_rotation_last_success_timestamp to ~now.
  T04 — failure event: writes KsmRotationEvent with outcome=failure.
  T05 — failure event: increments kms_rotations_total{outcome=failure},
        does NOT move kms_rotation_last_success_timestamp.
  T06 — critical event: writes KsmRotationEvent with outcome=critical +
        increments kms_rotations_total{outcome=critical}.
  T07 — end-to-end: KSMRotationScheduler.trigger_now() with the replica
        handler drives an actual audit write via AuditLogWriter (no tuple
        passed to write()), verified from the on-disk JSON record.
  T08 — audit-write failure still increments the metric (finally block) and
        propagates the exception (fail loud, not swallowed).
"""
from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
ENTRYPOINT_SRC = SRC / "backoffice" / "entrypoint.py"


def _entrypoint_source() -> str:
    return ENTRYPOINT_SRC.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Group 1 — AST: wiring + handler-body verification (no import of entrypoint)
# ---------------------------------------------------------------------------

class TestKsmRotationHandlerWiring:
    """G1: entrypoint.py source actually wires on_event, not None/omitted."""

    def _find_scheduler_call(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
                if name == "KSMRotationScheduler":
                    return node
        return None

    def _find_handler_func(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_make_ksm_rotation_event_handler":
                return node
        return None

    def test_scheduler_construction_passes_on_event_kwarg(self):
        """KSMRotationScheduler(...) call must carry an on_event= kwarg."""
        tree = ast.parse(_entrypoint_source())
        call = self._find_scheduler_call(tree)
        assert call is not None, "Could not find KSMRotationScheduler(...) construction call"
        kwargs = {kw.arg for kw in call.keywords}
        assert "on_event" in kwargs, (
            f"KSMRotationScheduler(...) missing on_event= kwarg — "
            f"rotation events still unobservable (YSG-RISK-153); found kwargs: {kwargs}"
        )

    def test_on_event_kwarg_is_not_none_literal(self):
        """on_event= must not be a None literal (that's the pre-fix bug)."""
        tree = ast.parse(_entrypoint_source())
        call = self._find_scheduler_call(tree)
        assert call is not None
        for kw in call.keywords:
            if kw.arg == "on_event":
                is_none_const = isinstance(kw.value, ast.Constant) and kw.value.value is None
                assert not is_none_const, "on_event= must not be wired to a None literal"
                return
        pytest.fail("on_event kwarg not found after earlier assertion passed")

    def test_handler_function_defined(self):
        """_make_ksm_rotation_event_handler must be defined at module scope."""
        tree = ast.parse(_entrypoint_source())
        assert self._find_handler_func(tree) is not None, (
            "_make_ksm_rotation_event_handler is not defined in entrypoint.py"
        )

    def test_handler_constructs_ksm_rotation_event_not_tuple(self):
        """Handler body must construct a KsmRotationEvent (not pass (str, dict) through)."""
        tree = ast.parse(_entrypoint_source())
        fn = self._find_handler_func(tree)
        assert fn is not None
        src = ast.unparse(fn)
        assert "KsmRotationEvent(" in src, (
            "Handler must construct a KsmRotationEvent dataclass instance — "
            "passing (name, data) straight to audit_writer.write() would AttributeError"
        )

    def test_handler_calls_audit_writer_write(self):
        """Handler body must call .write(event) on the injected audit writer."""
        tree = ast.parse(_entrypoint_source())
        fn = self._find_handler_func(tree)
        assert fn is not None
        src = ast.unparse(fn)
        assert ".write(event)" in src or ".write(\n" in src or "audit_writer.write" in src, (
            "Handler must forward the constructed event to audit_writer.write()"
        )

    def test_handler_increments_rotations_total(self):
        """Handler body must call kms_rotations_total.labels(...).inc()."""
        tree = ast.parse(_entrypoint_source())
        fn = self._find_handler_func(tree)
        assert fn is not None
        src = ast.unparse(fn)
        assert "kms_rotations_total" in src and ".inc()" in src, (
            "Handler must increment kms_rotations_total — the metric the two "
            "live Prometheus alerts reference"
        )

    def test_handler_sets_last_success_timestamp(self):
        """Handler body must set kms_rotation_last_success_timestamp on success."""
        tree = ast.parse(_entrypoint_source())
        fn = self._find_handler_func(tree)
        assert fn is not None
        src = ast.unparse(fn)
        assert "kms_rotation_last_success_timestamp" in src and ".set(" in src, (
            "Handler must set kms_rotation_last_success_timestamp — the gauge "
            "the staleness alert references"
        )


# ---------------------------------------------------------------------------
# Replica of the fix — functionally identical to
# backoffice.entrypoint._make_ksm_rotation_event_handler, exercised against
# the REAL KsmRotationEvent / metrics-registry objects (see module docstring
# for why entrypoint.py itself is not imported).
# ---------------------------------------------------------------------------

def _make_handler_replica(audit_writer):
    from yashigani.audit.schema import EventType, KsmRotationEvent
    from yashigani.metrics.registry import (
        kms_rotations_total,
        kms_rotation_last_success_timestamp,
    )

    def _handler(name: str, data: dict) -> None:
        outcome = data.get("outcome", "") or "unknown"
        rotation_type = data.get("rotation_type", "") or "unknown"
        try:
            event = KsmRotationEvent(
                event_type=name,
                outcome=data.get("outcome", ""),
                rotation_type=data.get("rotation_type", ""),
                provider_name=data.get("provider", ""),
                new_token_handle=data.get("new_version"),
            )
            audit_writer.write(event)
        finally:
            kms_rotations_total.labels(
                outcome=outcome, rotation_type=rotation_type
            ).inc()
            if name == EventType.KSM_ROTATION_SUCCESS:
                kms_rotation_last_success_timestamp.set(time.time())

    return _handler


def _make_writer(tmp_path):
    from yashigani.audit.config import AuditConfig
    from yashigani.audit.writer import AuditLogWriter

    cfg = AuditConfig(
        log_path=str(tmp_path / "audit.log"),
        max_file_size_mb=10,
        retention_days=7,
    )
    return AuditLogWriter(config=cfg)


class TestKsmRotationEventHandler:
    """T01–T06, T08: handler behaviour against real audit schema + metrics."""

    def test_t01_success_writes_real_event_object(self, tmp_path):
        """T01: SUCCESS callback writes a KsmRotationEvent, not a (str, dict) tuple."""
        from yashigani.audit.schema import KsmRotationEvent

        captured = []
        writer = type("FakeWriter", (), {"write": lambda self, event: captured.append(event)})()

        handler = _make_handler_replica(writer)
        handler("KSM_ROTATION_SUCCESS", {
            "secret_key": "prod/db-password",
            "provider": "aws-secrets-manager",
            "outcome": "success",
            "rotation_type": "scheduled",
            "new_version": "v7",
        })

        assert len(captured) == 1
        event = captured[0]
        assert isinstance(event, KsmRotationEvent), (
            f"Expected KsmRotationEvent, got {type(event)!r} — "
            "on_event must not pass a (str, dict) pair to write()"
        )
        assert event.event_type == "KSM_ROTATION_SUCCESS"
        assert event.outcome == "success"
        assert event.rotation_type == "scheduled"
        assert event.provider_name == "aws-secrets-manager"
        assert event.new_token_handle == "v7"
        assert event.masking_applied is True

    def test_t02_success_increments_counter(self, tmp_path):
        """T02: kms_rotations_total{outcome=success,rotation_type=scheduled} increments."""
        from yashigani.metrics.registry import kms_rotations_total

        writer = type("FakeWriter", (), {"write": lambda self, event: None})()
        handler = _make_handler_replica(writer)

        before = kms_rotations_total.labels(
            outcome="success", rotation_type="scheduled"
        )._value.get()

        handler("KSM_ROTATION_SUCCESS", {
            "secret_key": "prod/db-password",
            "provider": "aws-secrets-manager",
            "outcome": "success",
            "rotation_type": "scheduled",
            "new_version": "v7",
        })

        after = kms_rotations_total.labels(
            outcome="success", rotation_type="scheduled"
        )._value.get()
        assert after == before + 1

    def test_t03_success_sets_last_success_timestamp(self, tmp_path):
        """T03: kms_rotation_last_success_timestamp is set to ~now() on SUCCESS."""
        from yashigani.metrics.registry import kms_rotation_last_success_timestamp

        writer = type("FakeWriter", (), {"write": lambda self, event: None})()
        handler = _make_handler_replica(writer)

        before_call = time.time()
        handler("KSM_ROTATION_SUCCESS", {
            "secret_key": "prod/db-password",
            "provider": "aws-secrets-manager",
            "outcome": "success",
            "rotation_type": "manual",
        })
        after_call = time.time()

        value = kms_rotation_last_success_timestamp._value.get()
        assert before_call - 1 <= value <= after_call + 1, (
            f"last_success_timestamp={value} not within [{before_call}, {after_call}]"
        )

    def test_t04_failure_writes_event_with_failure_outcome(self, tmp_path):
        """T04: FAILURE callback writes a KsmRotationEvent with outcome=failure."""
        from yashigani.audit.schema import KsmRotationEvent

        captured = []
        writer = type("FakeWriter", (), {"write": lambda self, event: captured.append(event)})()
        handler = _make_handler_replica(writer)

        handler("KSM_ROTATION_FAILURE", {
            "secret_key": "prod/db-password",
            "provider": "aws-secrets-manager",
            "outcome": "failure",
            "rotation_type": "scheduled",
        })

        assert len(captured) == 1
        event = captured[0]
        assert isinstance(event, KsmRotationEvent)
        assert event.event_type == "KSM_ROTATION_FAILURE"
        assert event.outcome == "failure"

    def test_t05_failure_increments_counter_no_false_success(self, tmp_path):
        """T05: FAILURE increments outcome=failure and does NOT move last_success_timestamp."""
        from yashigani.metrics.registry import (
            kms_rotations_total,
            kms_rotation_last_success_timestamp,
        )

        writer = type("FakeWriter", (), {"write": lambda self, event: None})()
        handler = _make_handler_replica(writer)

        # Prime the success gauge to a known sentinel value.
        kms_rotation_last_success_timestamp.set(12345.0)

        before = kms_rotations_total.labels(
            outcome="failure", rotation_type="scheduled"
        )._value.get()

        handler("KSM_ROTATION_FAILURE", {
            "secret_key": "prod/db-password",
            "provider": "aws-secrets-manager",
            "outcome": "failure",
            "rotation_type": "scheduled",
        })

        after = kms_rotations_total.labels(
            outcome="failure", rotation_type="scheduled"
        )._value.get()
        assert after == before + 1
        assert kms_rotation_last_success_timestamp._value.get() == 12345.0, (
            "FAILURE must not update the last-success gauge"
        )

    def test_t06_critical_writes_event_and_increments_counter(self, tmp_path):
        """T06: CRITICAL callback writes event with outcome=critical + increments counter."""
        from yashigani.audit.schema import KsmRotationEvent
        from yashigani.metrics.registry import kms_rotations_total

        captured = []
        writer = type("FakeWriter", (), {"write": lambda self, event: captured.append(event)})()
        handler = _make_handler_replica(writer)

        before = kms_rotations_total.labels(
            outcome="critical", rotation_type="unknown"
        )._value.get()

        handler("KSM_ROTATION_CRITICAL", {
            "secret_key": "prod/db-password",
            "provider": "aws-secrets-manager",
            "outcome": "critical",
        })

        after = kms_rotations_total.labels(
            outcome="critical", rotation_type="unknown"
        )._value.get()
        assert after == before + 1

        assert len(captured) == 1
        event = captured[0]
        assert isinstance(event, KsmRotationEvent)
        assert event.event_type == "KSM_ROTATION_CRITICAL"
        assert event.outcome == "critical"

    def test_t08_audit_write_failure_still_increments_metric_and_reraises(self, tmp_path):
        """T08: If audit_writer.write() raises, the counter still increments (finally),
        and the exception is NOT swallowed (fail loud, no silent drop)."""
        from yashigani.metrics.registry import kms_rotations_total

        class _ExplodingWriter:
            def write(self, event):
                raise RuntimeError("simulated audit volume failure")

        handler = _make_handler_replica(_ExplodingWriter())

        before = kms_rotations_total.labels(
            outcome="success", rotation_type="scheduled"
        )._value.get()

        with pytest.raises(RuntimeError, match="simulated audit volume failure"):
            handler("KSM_ROTATION_SUCCESS", {
                "secret_key": "prod/db-password",
                "provider": "aws-secrets-manager",
                "outcome": "success",
                "rotation_type": "scheduled",
            })

        after = kms_rotations_total.labels(
            outcome="success", rotation_type="scheduled"
        )._value.get()
        assert after == before + 1, (
            "Metric must still increment even when the audit write raises"
        )


class TestKsmRotationEndToEnd:
    """T07: real KSMRotationScheduler + real AuditLogWriter, wired via the replica handler."""

    def test_t07_trigger_now_writes_real_audit_event(self, tmp_path):
        """T07: scheduler.trigger_now() with the fix's handler writes a genuine
        audit record to disk via AuditLogWriter.write(event) — proves the
        (str, dict) -> AuditEvent adapter works end-to-end, not just against a
        fake writer."""
        from yashigani.kms.base import KSMProvider
        from yashigani.kms.rotation import KSMRotationScheduler

        class _MockProvider(KSMProvider):
            def __init__(self):
                self._stored = {"dev/key": "old"}

            def get_secret(self, key):
                return self._stored[key]

            def set_secret(self, key, value):
                self._stored[key] = value

            def rotate_secret(self, key, new_value):
                self._stored[key] = new_value
                return "v9"

            def revoke_token(self, key):
                pass

            def list_secrets(self, prefix=None):
                return []

            def delete_secret(self, key):
                pass

            def health_check(self):
                return True

            @property
            def provider_name(self):
                return "mock-provider"

            @property
            def environment_scope(self):
                return "dev"

        writer = _make_writer(tmp_path)
        provider = _MockProvider()
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
            on_event=_make_handler_replica(writer),
        )

        scheduler.trigger_now()
        writer.close()

        log_path = tmp_path / "audit.log"
        assert log_path.exists()
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        import json
        record = json.loads(lines[0])
        assert record["event_type"] == "KSM_ROTATION_SUCCESS"
        assert record["outcome"] == "success"
        assert record["rotation_type"] == "manual"
        assert record["provider_name"] == "mock-provider"
