"""
Regression test -- v4.1.2 YSG-RISK-148 (MED): DELETE /admin/audit/sinks/queue
documented since 2026-05-02 but never implemented (always 404).

Fix:
  - audit/sinks.py: PostgresSink.drain_now() (drains the asyncio.Queue via
    get_nowait + _flush_batch), SiemSink.drain_now() (pops the Redis queue +
    delivers directly), MultiSinkAuditWriter.drain_queues() (fans out to
    every sink that exposes drain_now(); sinks without one, e.g. FileSink,
    are simply omitted).
  - routes/audit_sinks.py: new DELETE /admin/audit/sinks/queue endpoint,
    fail-closed 503 if audit_writer is unavailable.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_FAKE_SESSION = SimpleNamespace(account_id="test-admin", account_tier="admin")


def _run(coro):
    return asyncio.run(coro)


class TestPostgresSinkDrainNow:
    def test_drain_now_flushes_queued_events_and_returns_count(self):
        from yashigani.audit.sinks import PostgresSink

        flushed_batches = []

        async def _fake_flush_batch(self, batch):
            flushed_batches.append(list(batch))

        with patch.object(PostgresSink, "_flush_batch", _fake_flush_batch):
            sink = PostgresSink(pool_getter=lambda: None, chain_service=None, require_chain=False)
            sink.enqueue_nowait({"event_type": "A"})
            sink.enqueue_nowait({"event_type": "B"})
            count = _run(sink.drain_now())

        assert count == 2
        assert len(flushed_batches) == 1
        assert [e["event_type"] for e in flushed_batches[0]] == ["A", "B"]

    def test_drain_now_on_empty_queue_returns_zero_and_does_not_flush(self):
        from yashigani.audit.sinks import PostgresSink

        called = []

        async def _fake_flush_batch(self, batch):
            called.append(batch)

        with patch.object(PostgresSink, "_flush_batch", _fake_flush_batch):
            sink = PostgresSink(pool_getter=lambda: None, chain_service=None, require_chain=False)
            count = _run(sink.drain_now())

        assert count == 0
        assert called == []


class TestSiemSinkDrainNow:
    def test_drain_now_no_redis_is_a_noop(self):
        from yashigani.audit.sinks import SiemSink

        sink = SiemSink(siem_type="splunk", endpoint="https://x", token="t", redis_client=None)
        count = _run(sink.drain_now())
        assert count == 0

    def test_drain_now_pops_and_delivers_queued_events(self):
        fakeredis = pytest.importorskip("fakeredis", reason="fakeredis not installed")
        import json

        from yashigani.audit.sinks import SiemSink

        r = fakeredis.FakeRedis(decode_responses=True)
        sink = SiemSink(siem_type="splunk", endpoint="https://x", token="t", redis_client=r, sink_name="test")
        r.rpush(sink._queue_key, json.dumps({"event_type": "SIEM_1"}))
        r.rpush(sink._queue_key, json.dumps({"event_type": "SIEM_2"}))

        delivered = []

        async def _fake_deliver_direct(event):
            delivered.append(event)

        with patch.object(sink, "_deliver_direct", _fake_deliver_direct):
            count = _run(sink.drain_now())

        assert count == 2
        assert [e["event_type"] for e in delivered] == ["SIEM_1", "SIEM_2"]
        assert r.llen(sink._queue_key) == 0


class TestMultiSinkAuditWriterDrainQueues:
    def test_drain_queues_fans_out_to_sinks_with_drain_now_only(self):
        from yashigani.audit.sinks import MultiSinkAuditWriter

        class FakeSinkWithDrain:
            name = "postgres"

            async def drain_now(self):
                return 3

        class FakeSinkNoDrain:
            name = "file"

        writer = MultiSinkAuditWriter([FakeSinkWithDrain(), FakeSinkNoDrain()])
        result = _run(writer.drain_queues())
        assert result == {"postgres": 3}
        assert "file" not in result

    def test_drain_queues_records_minus_one_on_error_but_does_not_raise(self):
        from yashigani.audit.sinks import MultiSinkAuditWriter

        class FailingSink:
            name = "siem_splunk"

            async def drain_now(self):
                raise RuntimeError("boom")

        writer = MultiSinkAuditWriter([FailingSink()])
        result = _run(writer.drain_queues())
        assert result == {"siem_splunk": -1}


def _make_app():
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.audit_sinks import audit_sinks_router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(audit_sinks_router, tags=["audit-sinks"])
    return app


class TestDrainQueueEndpoint:
    def test_delete_queue_503_when_audit_writer_unavailable(self):
        app = _make_app()
        client = TestClient(app)
        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", None):
            resp = client.delete("/admin/audit/sinks/queue")
        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "audit_writer_unavailable"

    def test_delete_queue_drains_and_returns_per_sink_counts(self):
        app = _make_app()
        client = TestClient(app)

        fake_writer = SimpleNamespace(drain_queues=AsyncMock(return_value={"postgres": 5}))
        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", fake_writer):
            resp = client.delete("/admin/audit/sinks/queue")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "drained"
        assert body["sinks"] == {"postgres": 5}

    def test_delete_queue_legacy_writer_without_drain_queues_reports_honestly(self):
        """A writer with no drain_queues() (legacy/single-sink) must NOT be
        reported as having drained anything — honest empty result, not a
        fabricated success."""
        app = _make_app()
        client = TestClient(app)

        class LegacyWriter:
            def write(self, event):
                pass

        with patch("yashigani.backoffice.state.backoffice_state.audit_writer", LegacyWriter()):
            resp = client.delete("/admin/audit/sinks/queue")

        assert resp.status_code == 200
        assert resp.json() == {"status": "no_queued_sinks", "sinks": {}}
