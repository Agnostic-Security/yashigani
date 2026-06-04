"""
Multi-sink audit writer — Phase 10 / v0.9.0 Production Hardening (SC-04).

Sinks:
  FileSink      — synchronous RotatingFileHandler (wraps existing AuditLogWriter)
  PostgresSink  — async batch writer to audit_events table via asyncpg
  SiemSink      — Redis-backed async forwarding: Splunk HEC, Elasticsearch bulk API, or Wazuh
                  PostgreSQL and file sinks remain synchronous per design.

Architecture:
  MultiSinkAuditWriter.write(event) is synchronous (compatible with existing call sites).
  FileSink writes synchronously — audit trail is never lost even if Postgres is down.
  PostgresSink enqueues to asyncio.Queue and drains in a background task.
  SiemSink (SC-04): HTTP-based SIEM delivery is moved to a Redis-backed queue.
    - RPUSH yashigani:siem_queue:{sink_name} for each event JSON.
    - SiemWorker pops and delivers in configurable batches (1-100).
    - Dead-letter queue: yashigani:siem_dlq:{sink_name} after 3 retries with
      exponential backoff (2s, 4s, 8s).
    - Queue full → drop + increment Prometheus counter.
  Prometheus gauges:
    yashigani_siem_queue_depth{sink}  — current Redis queue depth
    yashigani_siem_dlq_depth{sink}    — current DLQ depth
    yashigani_audit_chain_breaks_total — chain breaks (populated by audit_verify.py)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import threading
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis queue constants (SC-04)
# ---------------------------------------------------------------------------

_SIEM_QUEUE_PREFIX = "yashigani:siem_queue:"
_SIEM_DLQ_PREFIX = "yashigani:siem_dlq:"
_SIEM_MAX_RETRIES = 3
_SIEM_BACKOFF_SECONDS = [2.0, 4.0, 8.0]   # exponential backoff per retry
_SIEM_DEFAULT_BATCH_SIZE = 50              # events per delivery batch
_SIEM_BATCH_MIN = 1
_SIEM_BATCH_MAX = 100


class AuditSink(ABC):
    name: str

    @abstractmethod
    async def write(self, event: dict) -> None: ...

    @abstractmethod
    async def last_write_ts(self) -> Optional[datetime]: ...


class FileSink(AuditSink):
    """Synchronous file sink — wraps the existing AuditLogWriter."""
    name = "file"

    def __init__(self, writer) -> None:
        self._writer = writer
        self._last_write: Optional[datetime] = None

    async def write(self, event: dict) -> None:
        try:
            self._writer._write_raw(json.dumps(event))
            self._last_write = datetime.now(timezone.utc)
        except Exception as exc:
            logger.error("FileSink write error: %s", exc)

    async def last_write_ts(self) -> Optional[datetime]:
        return self._last_write


class PostgresSink(AuditSink):
    """Async batch sink — writes audit_events rows via asyncpg.

    LU-AMEND-01 (wave 2): accepts an AuditChainService instance that computes
    prev_hash + event_hash before each INSERT.  If chain_service is None, the
    hash columns are written as NULL (legacy / test path with no chain).
    """
    name = "postgres"
    MAX_QUEUE_DEPTH = 1000

    def __init__(self, pool_getter, chain_service=None, *, require_chain: bool = False) -> None:
        """
        Args:
            pool_getter: zero-argument callable returning an asyncpg pool.
            chain_service: AuditChainService instance.  When supplied, every
                INSERT populates prev_hash and event_hash.
            require_chain: v2.25.2 (Lu wire-sink-gate P2, irrevocable chain).
                When True (the production wired path — see
                build_postgres_audit_sink), the sink is constructed
                immutable-by-construction:
                  * chain_service MUST be non-None (else __init__ raises);
                  * a hash-computation failure REJECTS the event (it is NOT
                    written with NULL chain links).
                The DB additionally enforces a CHECK (prev_hash IS NOT NULL AND
                event_hash IS NOT NULL) NOT VALID constraint (migration 0015),
                so even a bypassed app guard cannot land an unchained row.
                require_chain=False is the legacy/test path (no chain).

        Raises:
            ValueError: if require_chain=True but chain_service is None.
        """
        if require_chain and chain_service is None:
            raise ValueError(
                "PostgresSink(require_chain=True) requires a non-None chain_service — "
                "an unchained audit sink would defeat the tamper-evident guarantee "
                "(Lu wire-sink-gate P2 / irrevocable chain)."
            )
        self._pool_getter = pool_getter
        self._chain_service = chain_service
        self._require_chain = require_chain
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_DEPTH)
        self._last_write: Optional[datetime] = None
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._drain_loop())

    async def _drain_loop(self) -> None:
        BATCH_SIZE = 50
        DRAIN_INTERVAL = 2.0
        while True:
            batch: list[dict] = []
            try:
                deadline = asyncio.get_event_loop().time() + DRAIN_INTERVAL
                while len(batch) < BATCH_SIZE:
                    timeout = max(0.0, deadline - asyncio.get_event_loop().time())
                    try:
                        item = await asyncio.wait_for(
                            self._queue.get(), timeout=timeout
                        )
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break
                if batch:
                    await self._flush_batch(batch)
            except asyncio.CancelledError:
                if batch:
                    await self._flush_batch(batch)
                raise
            except Exception as exc:
                logger.error("PostgresSink drain error: %s", exc)
                await asyncio.sleep(5)

    async def _flush_batch(self, batch: list[dict]) -> None:
        from yashigani.db.models import INSERT_AUDIT_EVENT
        pool = self._pool_getter()
        async with pool.acquire() as conn:
            async with conn.transaction():
                for event in batch:
                    tenant_id = event.get("tenant_id") or "00000000-0000-0000-0000-000000000000"
                    await conn.execute(
                        "SELECT set_config('app.tenant_id', $1, true)",
                        str(tenant_id),
                    )
                    req_id = event.get("request_id")

                    # LU-AMEND-01 wave 2: compute hash-chain fields before INSERT.
                    # The AuditChainService lock serialises these within the process;
                    # the batch loop serialises them within this flush call.
                    # LU-AMEND-01 wave 3: INSERTs are sequential within a single
                    # transaction so the DB-assigned seq values are strictly
                    # monotonic in insertion order — the same order in which
                    # compute_hashes_for_event() is called here.
                    prev_hash: Optional[str] = None
                    event_hash: Optional[str] = None
                    if self._chain_service is not None:
                        try:
                            prev_hash, event_hash = self._chain_service.compute_hashes_for_event(event)
                        except Exception as exc:
                            # v2.25.2 (irrevocable chain): on the require_chain
                            # (production) path, a hash-computation failure must
                            # REJECT the event, not write it unchained.  Skip the
                            # INSERT; the canonical file sink still has the event,
                            # so the trail is not lost — only the DB mirror drops
                            # this one row, which the checkpoint job surfaces as a
                            # gap.  On the legacy path we preserve the old
                            # behaviour (NULL hashes).
                            if self._require_chain:
                                try:
                                    from yashigani.metrics.registry import audit_queue_overflow_total
                                    audit_queue_overflow_total.inc()
                                except Exception:
                                    pass
                                logger.error(
                                    "PostgresSink: chain hash computation failed — "
                                    "REJECTING event (require_chain on): %s",
                                    exc,
                                )
                                continue
                            logger.error(
                                "PostgresSink: chain hash computation failed — INSERT will have NULL hashes: %s",
                                exc,
                            )
                    elif self._require_chain:
                        # Defensive: should be unreachable (__init__ rejects
                        # chain_service=None when require_chain).  Never write an
                        # unchained row on the production path.
                        logger.error(
                            "PostgresSink: require_chain on but chain_service is None — "
                            "REJECTING event"
                        )
                        continue

                    # RETURNING seq (wave 3): capture the authoritative sequence
                    # value for logging / verification. The seq column is the
                    # canonical ordering key; its value is DB-assigned (BIGSERIAL).
                    row = await conn.fetchrow(
                        INSERT_AUDIT_EVENT,
                        uuid.UUID(str(tenant_id)),
                        event.get("event_type", "UNKNOWN"),
                        uuid.UUID(str(req_id)) if req_id else None,
                        event.get("session_id"),
                        event.get("agent_id"),
                        event.get("action", "UNKNOWN"),
                        event.get("reason"),
                        event.get("upstream_status"),
                        event.get("elapsed_ms"),
                        event.get("confidence_score"),
                        event.get("client_ip_hash"),
                        prev_hash,
                        event_hash,
                    )
                    if row is not None:
                        logger.debug(
                            "PostgresSink: inserted audit event seq=%s type=%s",
                            row["seq"],
                            event.get("event_type", "UNKNOWN"),
                        )
        self._last_write = datetime.now(timezone.utc)

    def enqueue_nowait(self, event: dict) -> bool:
        """Synchronous, non-blocking enqueue (loop-agnostic).

        v2.25.2: called from AuditLogWriter.write() (a sync method invoked from
        both sync and async request paths) so the DB sink does not depend on a
        running event loop at the call site.  asyncio.Queue.put_nowait() is
        thread-safe enough for our single-process fan-out: it only mutates the
        deque + wakes a waiter via call_soon_threadsafe internally when a loop
        is bound.  Returns True if enqueued, False if dropped (queue full).

        NEVER raises — queue-full is counted + logged and swallowed so the
        caller's request and the canonical file write are unaffected.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            try:
                from yashigani.metrics.registry import audit_queue_overflow_total
                audit_queue_overflow_total.inc()
            except Exception:
                pass
            logger.warning("PostgresSink queue full — audit event dropped")
            return False
        except Exception as exc:  # noqa: BLE001 — fan-out must never break caller
            logger.warning("PostgresSink enqueue error (dropped): %s", exc)
            return False

    async def write(self, event: dict) -> None:
        # Delegates to the sync enqueue path so there is a single, audited
        # drop-and-log code path for both async and sync callers.
        self.enqueue_nowait(event)

    async def last_write_ts(self) -> Optional[datetime]:
        return self._last_write


class SiemSink(AuditSink):
    """
    v0.9.0 (SC-04): HTTP-based SIEM delivery is Redis-backed and asynchronous.

    write() pushes the event JSON to ``yashigani:siem_queue:{name}`` via RPUSH.
    A SiemWorker background thread pops events and delivers them in batches.
    On exhausted retries the event is moved to the dead-letter queue (DLQ).

    Prometheus gauges (updated by SiemWorker):
        yashigani_siem_queue_depth{sink}  — main queue depth
        yashigani_siem_dlq_depth{sink}    — DLQ depth

    Fail-open: queue push errors are logged and counted, never propagated.
    """

    def __init__(
        self,
        siem_type: str,
        endpoint: str,
        token: str,
        redis_client=None,
        sink_name: Optional[str] = None,
        batch_size: int = _SIEM_DEFAULT_BATCH_SIZE,
    ) -> None:
        self._siem_type = siem_type   # "splunk" | "elasticsearch" | "wazuh"
        self._endpoint = endpoint
        self._token = token
        self._redis = redis_client
        self._sink_name = sink_name or siem_type
        self._batch_size = max(_SIEM_BATCH_MIN, min(_SIEM_BATCH_MAX, batch_size))
        self._last_write: Optional[datetime] = None
        self._queue_key = f"{_SIEM_QUEUE_PREFIX}{self._sink_name}"
        self._dlq_key = f"{_SIEM_DLQ_PREFIX}{self._sink_name}"

    @property
    def name(self) -> str:  # type: ignore[override]
        return f"siem_{self._sink_name}"

    async def write(self, event: dict) -> None:
        """
        Enqueue the event JSON to the Redis SIEM queue (RPUSH).
        Falls back to direct delivery if Redis is not configured.
        """
        if self._redis is None:
            # No Redis — deliver directly (legacy / test path)
            await self._deliver_direct(event)
            return

        try:
            payload = json.dumps(event, default=str)
            self._redis.rpush(self._queue_key, payload)
            self._update_queue_gauge()
        except Exception as exc:
            try:
                from yashigani.metrics.registry import siem_forward_errors_total
                siem_forward_errors_total.labels(siem=self._siem_type).inc()
            except Exception:
                pass
            logger.warning(
                "SiemSink(%s): Redis enqueue error — %s", self._sink_name, exc
            )

    async def _deliver_direct(self, event: dict) -> None:
        """Direct (non-queued) delivery — used when Redis is not available."""
        try:
            if self._siem_type == "splunk":
                await self._send_splunk(event)
            elif self._siem_type in ("elasticsearch", "wazuh"):
                await self._send_elasticsearch(event)
            self._last_write = datetime.now(timezone.utc)
        except Exception as exc:
            try:
                from yashigani.metrics.registry import siem_forward_errors_total
                siem_forward_errors_total.labels(siem=self._siem_type).inc()
            except Exception:
                pass
            logger.warning("SiemSink(%s) direct forward error: %s", self._sink_name, exc)

    def _update_queue_gauge(self) -> None:
        if self._redis is None:
            return
        try:
            from yashigani.metrics.registry import siem_queue_depth, siem_dlq_depth
            q_depth = self._redis.llen(self._queue_key) or 0
            d_depth = self._redis.llen(self._dlq_key) or 0
            siem_queue_depth.labels(sink=self._sink_name).set(q_depth)
            siem_dlq_depth.labels(sink=self._sink_name).set(d_depth)
        except Exception:
            pass

    async def _send_splunk(self, event: dict) -> None:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                self._endpoint,
                json={"event": event, "sourcetype": "yashigani_audit"},
                headers={"Authorization": f"Splunk {self._token}"},
            )

    async def _send_elasticsearch(self, event: dict) -> None:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            meta = json.dumps({"index": {"_index": "yashigani-audit"}})
            body = f"{meta}\n{json.dumps(event)}\n"
            await client.post(
                self._endpoint + "/_bulk",
                content=body.encode(),
                headers={
                    "Content-Type": "application/x-ndjson",
                    "Authorization": f"ApiKey {self._token}",
                },
            )

    async def last_write_ts(self) -> Optional[datetime]:
        return self._last_write


# ---------------------------------------------------------------------------
# SC-04: SiemWorker — Redis-queue consumer / delivery background thread
# ---------------------------------------------------------------------------

class SiemWorker:
    """
    Background worker thread that drains yashigani:siem_queue:{sink_name},
    delivers events to the SIEM endpoint in batches, and moves failed events
    to the dead-letter queue (DLQ) after exhausting retries.

    Usage::

        worker = SiemWorker(sink=siem_sink, poll_interval=1.0)
        worker.start()
        # ... application runs ...
        worker.stop()
    """

    def __init__(
        self,
        sink: SiemSink,
        poll_interval: float = 1.0,
    ) -> None:
        if sink._redis is None:
            raise ValueError("SiemWorker requires SiemSink to have a Redis client configured.")
        self._sink = sink
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"siem-worker-{self._sink._sink_name}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "SiemWorker(%s): started (batch_size=%d, poll=%.1fs)",
            self._sink._sink_name, self._sink._batch_size, self._poll_interval,
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("SiemWorker(%s): stopped", self._sink._sink_name)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._drain_batch()
            except Exception as exc:
                logger.error("SiemWorker(%s) drain error: %s", self._sink._sink_name, exc)
            self._stop_event.wait(timeout=self._poll_interval)

    def _drain_batch(self) -> None:
        r = self._sink._redis
        queue_key = self._sink._queue_key
        batch_size = self._sink._batch_size

        batch = []
        for _ in range(batch_size):
            raw = r.lpop(queue_key)
            if raw is None:
                break
            batch.append(raw)

        if not batch:
            return

        events = []
        for raw in batch:
            try:
                events.append(json.loads(raw if isinstance(raw, str) else raw.decode("utf-8")))
            except Exception as exc:
                logger.warning(
                    "SiemWorker(%s): malformed event in queue — %s", self._sink._sink_name, exc
                )

        for event in events:
            self._deliver_with_retry(event)

        self._sink._update_queue_gauge()

    def _deliver_with_retry(self, event: dict) -> None:
        """Deliver a single event with exponential backoff; send to DLQ on failure."""
        last_exc: Optional[Exception] = None
        for attempt, delay in enumerate(_SIEM_BACKOFF_SECONDS):
            try:
                # Synchronous delivery via a new event loop slice
                loop = asyncio.new_event_loop()
                try:
                    if self._sink._siem_type == "splunk":
                        loop.run_until_complete(self._sink._send_splunk(event))
                    elif self._sink._siem_type in ("elasticsearch", "wazuh"):
                        loop.run_until_complete(self._sink._send_elasticsearch(event))
                    else:
                        raise ValueError(f"Unknown SIEM type: {self._sink._siem_type!r}")
                finally:
                    loop.close()
                self._sink._last_write = datetime.now(timezone.utc)
                return
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "SiemWorker(%s): delivery attempt %d/%d failed — %s",
                    self._sink._sink_name, attempt + 1, _SIEM_MAX_RETRIES, exc,
                )
                if attempt < _SIEM_MAX_RETRIES - 1:
                    time.sleep(delay)

        # All retries exhausted — move to DLQ
        self._send_to_dlq(event, str(last_exc))

    def _send_to_dlq(self, event: dict, error: str) -> None:
        """Push failed event to the dead-letter queue."""
        dlq_key = self._sink._dlq_key
        try:
            record = json.dumps({
                "event": event,
                "error": error,
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "sink": self._sink._sink_name,
            }, default=str)
            self._sink._redis.rpush(dlq_key, record)
            self._sink._update_queue_gauge()
            logger.error(
                "SiemWorker(%s): event %s moved to DLQ after %d retries",
                self._sink._sink_name,
                event.get("audit_event_id", "<unknown>"),
                _SIEM_MAX_RETRIES,
            )
        except Exception as exc:
            logger.error(
                "SiemWorker(%s): DLQ write failed for event %s — %s",
                self._sink._sink_name,
                event.get("audit_event_id", "<unknown>"),
                exc,
            )


# ---------------------------------------------------------------------------
# v2.25.2 — DB audit-sink wiring helpers
# ---------------------------------------------------------------------------
#
# These helpers are the single construction point for the PostgresSink + the
# AuditChainService that backs the audit_events hash chain, so both the gateway
# and backoffice lifespans wire the DB sink identically.  The file sink remains
# the canonical durability anchor; the DB sink is a fire-and-forget mirror.


def _audit_checkpoint_signing() -> tuple[Optional[Any], str]:
    """Resolve the optional checkpoint signing key path + SPIFFE id from env.

    Returns (signing_key_path | None, signing_spiffe_id).  When the key path is
    unset or the file is missing, returns (None, spiffe_id) — the chain service
    + checkpoint scheduler then write UNSIGNED checkpoints (still tamper-evident
    via the merkle root; signature is an additional non-repudiation layer).
    """
    import os
    from pathlib import Path

    key_path_str = os.environ.get("YASHIGANI_AUDIT_SIGNING_KEY_PATH", "").strip()
    spiffe_id = os.environ.get(
        "YASHIGANI_AUDIT_SIGNING_SPIFFE_ID",
        "spiffe://yashigani.internal/audit",
    ).strip()
    if key_path_str:
        kp = Path(key_path_str)
        if kp.exists():
            return kp, spiffe_id
        logger.warning(
            "YASHIGANI_AUDIT_SIGNING_KEY_PATH=%s does not exist — "
            "daily audit checkpoints will be written UNSIGNED",
            key_path_str,
        )
    return None, spiffe_id


def build_postgres_audit_sink(pool_getter):
    """Construct + start a PostgresSink with a row-level hash-chain service.

    Args:
        pool_getter: zero-arg callable returning the asyncpg pool
            (yashigani.db.get_pool).  Reused from the existing DB pool — no
            second pool is created.

    Returns:
        (PostgresSink, AuditChainService) — the sink is ALREADY started
        (drain loop scheduled on the running loop); the chain service is the
        same instance to pass to the daily checkpoint scheduler so the
        in-process chain pointer is shared.

    The caller MUST be inside a running event loop (call from the FastAPI
    lifespan) so PostgresSink.start() can schedule its drain task.
    """
    from yashigani.audit.chain import AuditChainService

    key_path, spiffe_id = _audit_checkpoint_signing()
    # Row-level hashing (compute_hashes_for_event) needs no signing key; the
    # key only matters for the daily checkpoint signature.  We hand the same
    # service to both so the chain pointer + signing config are shared.
    chain_service = AuditChainService(
        signing_key_path=key_path,
        signing_spiffe_id=spiffe_id,
    )
    # v2.25.2 (Lu wire-sink-gate P2 / irrevocable chain): the wired production
    # path is immutable-by-construction — require_chain=True so the sink can
    # never silently write an unchained (NULL-hash) row.
    sink = PostgresSink(
        pool_getter=pool_getter,
        chain_service=chain_service,
        require_chain=True,
    )
    sink.start()
    logger.info(
        "PostgresSink started (chain hashing ON [required], checkpoint signing=%s)",
        "ON" if key_path is not None else "OFF",
    )
    return sink, chain_service


def stop_postgres_audit_sink(sink) -> None:
    """Gracefully drain + stop a PostgresSink (call from lifespan shutdown).

    Cancels the drain task; the drain loop flushes the in-flight batch on
    CancelledError (see PostgresSink._drain_loop), so events already enqueued
    are persisted before the loop stops.  Never raises.
    """
    if sink is None:
        return
    try:
        task = getattr(sink, "_task", None)
        if task is not None and not task.done():
            task.cancel()
            logger.info("PostgresSink drain task cancelled — final batch will flush")
    except Exception as exc:  # noqa: BLE001 — shutdown must not raise
        logger.warning("PostgresSink stop error (ignored): %s", exc)


class MultiSinkAuditWriter:
    """
    Drop-in replacement for AuditLogWriter.
    write() is synchronous — compatible with all existing call sites.
    Each event is dispatched to all registered sinks.
    """

    def __init__(self, sinks: list[AuditSink]) -> None:
        self._sinks = sinks

    def write(self, event: Any) -> None:
        try:
            if hasattr(event, "model_dump"):
                event_dict = event.model_dump()
            elif hasattr(event, "__dict__"):
                event_dict = dict(event.__dict__)
            else:
                event_dict = dict(event)

            loop = asyncio.get_event_loop()
            for sink in self._sinks:
                try:
                    if loop.is_running():
                        asyncio.ensure_future(sink.write(event_dict))
                    else:
                        loop.run_until_complete(sink.write(event_dict))
                except Exception as exc:
                    logger.error("Sink %s dispatch error: %s", sink.name, exc)
        except Exception as exc:
            logger.error("MultiSinkAuditWriter serialization error: %s", exc)

    def start_async_sinks(self) -> None:
        """Call from async context after event loop is running."""
        for sink in self._sinks:
            if hasattr(sink, "start"):
                sink.start()

    async def status(self) -> dict:
        result = {}
        for sink in self._sinks:
            ts = await sink.last_write_ts()
            result[sink.name] = {
                "last_write": ts.isoformat() if ts else None,
            }
        return result
