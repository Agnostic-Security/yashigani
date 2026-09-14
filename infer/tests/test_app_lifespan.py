# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Regression tests for the app-lifespan defects — YSG-RISK-296/299/300.

These three are the "fine in a recycled container, broken in a long-lived host
process" class. Each test below fails on the pre-fix tree.

Note what is being tested: the WIRING, not the function bodies.
`idle_unload_sweep()` was already covered by unit tests in isolation and still
had zero callers anywhere in the tree — testing the body is exactly what let
YSG-RISK-300 survive. So these drive the real app lifespan.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator

import pytest
from fastapi.testclient import TestClient

from kuroshio.app import create_app


class _FakeUpstream:
    def __init__(self) -> None:
        self.closed = 0

    async def request_json(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
        raise AssertionError("not called")

    async def stream_lines(self, url: str, json_body: dict[str, Any]) -> AsyncIterator[str]:
        raise AssertionError("not called")
        yield ""  # pragma: no cover

    async def aclose(self) -> None:
        self.closed += 1


class _RecordingSupervisor:
    """Minimal Supervisor stand-in — only what the lifespan touches."""

    def __init__(self, resident: list[str] | None = None) -> None:
        self._resident = list(resident or [])
        self.unloaded: list[str] = []
        self.sweeps = 0

    @property
    def resident_shas(self) -> list[str]:
        return list(self._resident)

    def unload(self, sha256: str) -> bool:
        self.unloaded.append(sha256)
        if sha256 in self._resident:
            self._resident.remove(sha256)
            return True
        return False

    def idle_unload_sweep(self) -> list[str]:
        self.sweeps += 1
        return []


def _app(supervisor: Any, upstream: Any, **kw: Any):
    return create_app(
        blob_store=object(),  # type: ignore[arg-type] - lifespan never touches it
        supervisor=supervisor,
        upstream=upstream,
        **kw,
    )


# --- YSG-RISK-299: resident instances must be unloaded on shutdown ---------


def test_shutdown_unloads_every_resident_instance() -> None:
    sup = _RecordingSupervisor(["a" * 64, "b" * 64])
    app = _app(sup, _FakeUpstream())

    with TestClient(app):
        pass  # enter + exit drives startup and shutdown

    assert sorted(sup.unloaded) == sorted(["a" * 64, "b" * 64]), (
        "llama-server children outlived the supervisor — on launchd they are "
        "reparented to init and keep holding a port and a Metal context "
        "(YSG-RISK-299)"
    )


def test_shutdown_is_clean_when_nothing_is_resident() -> None:
    sup = _RecordingSupervisor([])
    with TestClient(_app(sup, _FakeUpstream())):
        pass
    assert sup.unloaded == []


# --- YSG-RISK-296: the pooled upstream client must be released -------------


def test_shutdown_closes_the_pooled_upstream_client() -> None:
    up = _FakeUpstream()
    with TestClient(_app(_RecordingSupervisor(), up)):
        pass
    assert up.closed == 1


def test_shutdown_tolerates_an_upstream_without_aclose() -> None:
    """`UpstreamClient` is a narrow Protocol; fakes need not implement aclose."""

    class _Bare:
        async def request_json(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
            raise AssertionError("not called")

        async def stream_lines(self, url: str, json_body: dict[str, Any]) -> AsyncIterator[str]:
            raise AssertionError("not called")
            yield ""  # pragma: no cover

    with TestClient(_app(_RecordingSupervisor(), _Bare())):
        pass  # must not raise


# --- YSG-RISK-300: the idle sweep must actually be scheduled --------------


@pytest.mark.asyncio
async def test_idle_sweep_is_actually_driven_by_the_running_app() -> None:
    sup = _RecordingSupervisor()
    app = _app(sup, _FakeUpstream(), idle_sweep_interval_seconds=0.01)

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.08)
        assert sup.sweeps >= 2, (
            f"idle_unload_sweep ran {sup.sweeps} times — it had zero callers in "
            "the whole tree, so YSG_KUROSHIO_IDLE_UNLOAD_SECONDS configured "
            "nothing on any platform (YSG-RISK-300)"
        )


@pytest.mark.asyncio
async def test_idle_sweep_task_is_cancelled_on_shutdown() -> None:
    sup = _RecordingSupervisor()
    app = _app(sup, _FakeUpstream(), idle_sweep_interval_seconds=0.01)

    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.05)
        # Must have been running, or "constant after shutdown" is vacuously
        # true — which is exactly what a never-scheduled sweeper looks like.
        assert sup.sweeps > 0, "sweeper never ran, so this test proves nothing"
    after_shutdown = sup.sweeps
    await asyncio.sleep(0.05)
    assert sup.sweeps == after_shutdown, "sweeper kept running after shutdown"


@pytest.mark.asyncio
async def test_a_failing_sweep_does_not_stop_later_sweeps() -> None:
    """One bad sweep must not silently kill idle-unload for the process lifetime."""

    class _Flaky(_RecordingSupervisor):
        def idle_unload_sweep(self) -> list[str]:
            self.sweeps += 1
            if self.sweeps == 1:
                raise RuntimeError("transient")
            return []

    sup = _Flaky()
    app = _app(sup, _FakeUpstream(), idle_sweep_interval_seconds=0.01)
    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.08)
    assert sup.sweeps >= 3
