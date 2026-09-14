# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""A cold model load must not freeze the process — YSG-RISK-290.

`Supervisor.load()` is synchronous and genuinely blocking: the wired
`HttpReadinessProbe` polls llama-server's `/health` in a `time.sleep` loop for
up to 60 seconds, and a configured `ProvenanceVerifier` re-hashes the blob
from disk. Every route called it directly from an `async def` handler, so one
cold load blocked the event loop and with it every other in-flight request,
across every tenant, `/healthz` included.

The test stages exactly that: a load that blocks a worker for 300ms while a
concurrent `/healthz` must still be served promptly. On the pre-fix tree the
health probe waits out the whole load; on the fixed tree it does not.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, AsyncIterator

import httpx
import pytest

from kuroshio.app import create_app

_BLOCK_SECONDS = 0.3
_SHA = "c" * 64


class _SlowLoadSupervisor:
    """Supervisor stand-in whose `load()` blocks the calling thread."""

    def __init__(self) -> None:
        self.loads = 0

    def load(self, model: Any, load_config: Any) -> Any:
        self.loads += 1
        time.sleep(_BLOCK_SECONDS)  # the readiness-poll / re-hash stand-in
        return type("_Inst", (), {"port": 39999, "sha256": _SHA})()

    # --- surface the routes and lifespan touch --------------------------
    def healthz(self) -> dict[str, Any]:
        return {"models": [], "unhealthy": []}

    @property
    def resident_shas(self) -> list[str]:
        return []

    def unload(self, sha256: str) -> bool:
        return False

    def idle_unload_sweep(self) -> list[str]:
        return []

    def acquire_request_slot(self, sha256: str) -> None:
        return None

    def release_request_slot(self, sha256: str) -> None:
        return None

    def touch(self, sha256: str) -> None:
        return None


class _FakeBlobStore:
    def find_by_name(self, name: str) -> Any:
        return type(
            "_Model",
            (),
            {"sha256": _SHA, "name": name, "metadata": {"chat_template": "x"}, "path": "/tmp/m"},
        )()


class _FakeUpstream:
    async def request_json(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
        return {"embedding": [0.0]}

    async def stream_lines(self, url: str, json_body: dict[str, Any]) -> AsyncIterator[str]:
        yield ""  # pragma: no cover


@pytest.mark.asyncio
async def test_healthz_is_served_while_a_cold_model_load_is_in_flight() -> None:
    app = create_app(
        blob_store=_FakeBlobStore(),  # type: ignore[arg-type]
        supervisor=_SlowLoadSupervisor(),  # type: ignore[arg-type]
        upstream=_FakeUpstream(),  # type: ignore[arg-type]
        idle_sweep_interval_seconds=None,
    )

    # Measure COMPLETION ORDER, not latency-from-a-timer. A blocked event loop
    # stalls the loop before any timer in this coroutine could start, so an
    # elapsed-time probe taken after the block cannot observe it — an earlier
    # draft of this test passed on the pre-fix tree for exactly that reason.
    # If the loop is free, the health probe finishes long before the 300ms
    # load. If it is blocked, neither can finish until the load releases it,
    # so they land together.
    done: dict[str, float] = {}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        async def _load() -> None:
            await client.post("/api/embeddings", json={"model": "m", "input": "hi"})
            done["load"] = time.monotonic()

        async def _health() -> None:
            await asyncio.sleep(0.02)  # let the load reach its blocking call first
            resp = await client.get("/healthz")
            done["health"] = time.monotonic()
            done["status"] = float(resp.status_code)

        start = time.monotonic()
        await asyncio.gather(_load(), _health())

    assert done["status"] == 200.0
    health_at = done["health"] - start
    load_at = done["load"] - start
    assert health_at < load_at * 0.5, (
        f"/healthz completed at {health_at:.3f}s and the cold load at "
        f"{load_at:.3f}s — the probe was stalled behind the load, so the event "
        "loop was blocked and every tenant's in-flight request waited with it "
        "(YSG-RISK-290)"
    )


@pytest.mark.asyncio
async def test_concurrent_loads_are_serialised_so_supervisor_state_stays_safe() -> None:
    """Offloading to a thread must not let two threads into `load()` at once.

    `Supervisor`'s `_instances`/`_inflight` dicts have no internal locking and
    were protected only by everything running on one event-loop thread. The
    lock preserves that invariant.
    """
    inside = 0
    max_concurrent = 0

    class _Counting(_SlowLoadSupervisor):
        def load(self, model: Any, load_config: Any) -> Any:
            nonlocal inside, max_concurrent
            inside += 1
            max_concurrent = max(max_concurrent, inside)
            try:
                time.sleep(0.05)
                return type("_Inst", (), {"port": 39999, "sha256": _SHA})()
            finally:
                inside -= 1

    app = create_app(
        blob_store=_FakeBlobStore(),  # type: ignore[arg-type]
        supervisor=_Counting(),  # type: ignore[arg-type]
        upstream=_FakeUpstream(),  # type: ignore[arg-type]
        idle_sweep_interval_seconds=None,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await asyncio.gather(
            *(client.post("/api/embeddings", json={"model": f"m{i}", "input": "x"}) for i in range(5))
        )

    assert max_concurrent == 1, (
        f"{max_concurrent} threads were inside Supervisor.load() at once — its "
        "dicts have no locking, so offloading without the lock is a data race"
    )
