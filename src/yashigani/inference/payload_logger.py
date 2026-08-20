"""
Async fire-and-forget inference payload logger.

Writes every inference call to the inference_events Postgres table.
The write is enqueued to an asyncio.Queue and drained in batches of 50
by a background task — the gateway request path is never blocked by PG I/O.

SHA-256 hash of the payload is stored in the clear (indexed for deduplication).
Payload content and response content are AES-256-CFB (OpenPGP) encrypted via
pgcrypto inside the INSERT SQL (pgp_sym_encrypt with cipher-algo=aes256 uses
current_setting('app.aes_key')).  pgcrypto uses OpenPGP symmetric format, not
AES-GCM; the cipher pin is applied via PGP_SYM_OPTS in db/postgres.py.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

BATCH_SIZE = 50
DRAIN_INTERVAL = 2.0  # seconds
MAX_QUEUE_DEPTH = 10_000


@dataclass
class InferenceRecord:
    tenant_id: str
    session_id: str
    agent_id: str
    payload_content: str
    response_content: Optional[str]
    classification_label: str
    classification_confidence: float
    backend_used: str
    latency_ms: int


class InferencePayloadLogger:
    """
    Call logger.log(...) from the gateway request path.
    Start the background drain task with logger.start().
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[InferenceRecord] = asyncio.Queue(
            maxsize=MAX_QUEUE_DEPTH
        )
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._drain_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def log(self, record: InferenceRecord) -> None:
        """Fire-and-forget enqueue. Drops record if queue is full."""
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            try:
                from yashigani.metrics.registry import inference_payload_log_queue_depth
                inference_payload_log_queue_depth.set(self._queue.qsize())
            except Exception:
                pass
            logger.warning(
                "InferencePayloadLogger queue full — record dropped "
                "(tenant=%s session=%s)", record.tenant_id, record.session_id
            )

    def queue_depth(self) -> int:
        return self._queue.qsize()

    async def _drain_loop(self) -> None:
        while True:
            batch: list[InferenceRecord] = []
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
                # Flush remaining items before exit
                if batch:
                    await self._flush_batch(batch)
                raise
            except Exception as exc:
                logger.error("InferencePayloadLogger drain error: %s", exc)
                await asyncio.sleep(5)

    async def _flush_batch(self, batch: list[InferenceRecord]) -> None:
        from yashigani.db.postgres import get_pool
        from yashigani.db.models import INSERT_INFERENCE_EVENT

        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                for rec in batch:
                    payload_hash = hashlib.sha256(
                        rec.payload_content.encode()
                    ).hexdigest()
                    await conn.execute(
                        "SELECT set_config('app.tenant_id', $1, true),"
                        "       set_config('app.aes_key', $2, true)",
                        rec.tenant_id,
                        _get_aes_key(),
                    )
                    await conn.execute(
                        INSERT_INFERENCE_EVENT,
                        uuid.UUID(rec.tenant_id),
                        rec.session_id,
                        rec.agent_id,
                        payload_hash,
                        len(rec.payload_content.encode()),
                        len(rec.response_content.encode()) if rec.response_content else None,
                        rec.payload_content,
                        rec.response_content or "",
                        rec.classification_label,
                        rec.classification_confidence,
                        rec.backend_used,
                        rec.latency_ms,
                    )
        logger.debug("InferencePayloadLogger flushed %d records", len(batch))


def _get_aes_key() -> str:
    import os
    return os.environ.get("YASHIGANI_DB_AES_KEY", "")
