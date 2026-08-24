# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Shared pytest fixtures + fake injectable implementations.

Hard constraint: this whole suite runs green with NO live ollama, NO
llama-server binary, NO network. Every fake below exists to make that true
while still exercising real code paths (blob store I/O on real tmp
filesystem paths, real GGUF byte parsing, real async FastAPI routing).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from tests.fixtures.gguf_builder import build_minimal_gguf
from kuroshio.adapters.downloader import Downloader
from kuroshio.blobstore.store import BlobStore
from kuroshio.supervisor.process import ProcessHandle, ProcessRunner
from kuroshio.upstream import UpstreamClient


@pytest.fixture()
def tmp_blob_store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobstore")


@pytest.fixture()
def minimal_gguf_bytes() -> bytes:
    return build_minimal_gguf()


@pytest.fixture()
def minimal_gguf_file(tmp_path: Path, minimal_gguf_bytes: bytes) -> Path:
    path = tmp_path / "tiny.gguf"
    path.write_bytes(minimal_gguf_bytes)
    return path


class FakeProcessHandle(ProcessHandle):
    """Fake process handle: never spawns anything real; tracks terminate() calls."""

    _next_pid = 1000

    def __init__(self) -> None:
        FakeProcessHandle._next_pid += 1
        self._pid = FakeProcessHandle._next_pid
        self._alive = True
        self.terminate_calls = 0

    @property
    def pid(self) -> int:
        return self._pid

    def is_alive(self) -> bool:
        return self._alive

    def terminate(self, *, timeout_seconds: float = 5.0) -> None:
        self.terminate_calls += 1
        self._alive = False


class FakeProcessRunner(ProcessRunner):
    """Fake process runner: records every spawn() call, returns FakeProcessHandle."""

    def __init__(self) -> None:
        self.spawned: list[dict[str, Any]] = []
        self.handles: list[FakeProcessHandle] = []

    def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> ProcessHandle:
        self.spawned.append({"binary": binary, "args": args, "env": env})
        handle = FakeProcessHandle()
        self.handles.append(handle)
        return handle


@pytest.fixture()
def fake_process_runner() -> FakeProcessRunner:
    return FakeProcessRunner()


class FakeDownloader(Downloader):
    """Fake downloader: writes canned bytes to `dest` instead of hitting the network."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.requested_urls: list[str] = []

    def download(self, url: str, dest: Path, *, headers: dict[str, str] | None = None) -> None:
        self.requested_urls.append(url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.payload)


class FailingDownloader(Downloader):
    """Fake downloader that always raises — for error-path tests."""

    def download(self, url: str, dest: Path, *, headers: dict[str, str] | None = None) -> None:
        raise ConnectionError(f"simulated network failure for {url}")


class FakeUpstreamClient(UpstreamClient):
    """Fake upstream client: returns canned JSON / canned SSE lines, no sockets."""

    def __init__(self, *, json_response: dict[str, Any] | None = None, sse_lines: list[str] | None = None) -> None:
        self.json_response = json_response or {}
        self.sse_lines = sse_lines or []
        self.requested_urls: list[str] = []
        self.requested_bodies: list[dict[str, Any]] = []

    async def request_json(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
        self.requested_urls.append(url)
        self.requested_bodies.append(json_body)
        return self.json_response

    async def stream_lines(self, url: str, json_body: dict[str, Any]) -> AsyncIterator[str]:
        self.requested_urls.append(url)
        self.requested_bodies.append(json_body)
        for line in self.sse_lines:
            yield line


__all__ = [
    "FakeProcessHandle",
    "FakeProcessRunner",
    "FakeDownloader",
    "FailingDownloader",
    "FakeUpstreamClient",
]
