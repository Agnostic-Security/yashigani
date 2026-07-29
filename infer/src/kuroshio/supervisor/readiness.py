# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Post-spawn llama-server readiness gate.

Red-Council Tom F4 (2026-07-29 design-review): `Supervisor.load()` spawns a
`llama-server` process and, previously, returned the instance the instant the
process was *spawned* — not the instant it was *ready to serve*. A real
`llama-server` needs to mmap/load the GGUF and warm its slots before its HTTP
port answers anything; between spawn and ready it either refuses the
connection or answers `/health` with `503`. The app forwards the very first
request to that port as soon as `load()` returns, so a request that arrives in
that window hits a not-yet-ready backend and fails. The unit-test suite never
saw this because the fake `ProcessRunner`/`UpstreamClient` are instantly
"ready" — there is no real port and no load latency to race against.

Fix: `Supervisor` takes an injectable `ReadinessProbe`. After a real spawn (only
— never on the already-resident fast path) it calls `wait_until_ready(port)`,
which blocks until the backend's `/health` reports ready or fails closed with
`BackendNotReadyError` once its own bounded timeout elapses. On failure the
supervisor terminates the just-spawned process and records no residency state,
so a backend that never comes up neither hangs the request nor leaks a process.

This module holds the real HTTP implementation (`HttpReadinessProbe`); like
`HttpxUpstreamClient` it is not exercised by the unit-test suite (that would
require a real `llama-server` listening on a port). The supervisor depends only
on the narrow `ReadinessProbe` Protocol declared in `supervisor.py`; tests
inject a fake.
"""

from __future__ import annotations

import time

from kuroshio.supervisor.supervisor import BackendNotReadyError


class HttpReadinessProbe:
    """Real `ReadinessProbe` — polls `http://{host}:{port}/health` until the
    llama-server backend reports ready (HTTP 200) or the bounded total timeout
    elapses (fail closed → `BackendNotReadyError`).

    llama-server answers `/health` with `503` while a model is still loading and
    `200` once it is ready to serve; a fresh process may also refuse the
    connection outright for a moment before the socket is up. Both are treated
    as "not ready yet, keep polling until the deadline", never as "ready".
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 60.0,
        poll_interval_seconds: float = 0.25,
        host: str = "127.0.0.1",
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._host = host

    def wait_until_ready(self, port: int) -> None:
        import httpx

        url = f"http://{self._host}:{port}/health"
        deadline = time.monotonic() + self._timeout_seconds
        while True:
            try:
                resp = httpx.get(url, timeout=self._poll_interval_seconds)
                if resp.status_code == 200:
                    return
            except httpx.HTTPError:
                # Connection refused / reset while the socket is still coming
                # up — indistinguishable from "still loading"; keep polling.
                pass
            if time.monotonic() >= deadline:
                raise BackendNotReadyError(
                    f"llama-server on port {port} did not report ready at {url} within {self._timeout_seconds}s"
                )
            time.sleep(self._poll_interval_seconds)


__all__ = ["HttpReadinessProbe"]
