# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Injectable process-spawn interface.

The supervisor never calls `subprocess` directly — every spawn goes through
`ProcessRunner`, so unit tests exercise the full lifecycle (spawn, idle
sweep, LRU eviction, keep-alive pin, healthz) without a real `llama-server`
binary on disk (hard constraint: no live process spawns in the test suite).
"""

from __future__ import annotations

import signal
import subprocess
from abc import ABC, abstractmethod


class ProcessHandle(ABC):
    """A handle to a spawned process (real or fake)."""

    @property
    @abstractmethod
    def pid(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def is_alive(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def terminate(self, *, timeout_seconds: float = 5.0) -> None:
        """Request graceful shutdown, escalating to a hard kill on timeout."""
        raise NotImplementedError


class ProcessRunner(ABC):
    """Spawns a process and returns a handle to it."""

    @abstractmethod
    def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> ProcessHandle:
        raise NotImplementedError


class SubprocessProcessHandle(ProcessHandle):
    def __init__(self, popen: subprocess.Popen[bytes]) -> None:
        self._popen = popen

    @property
    def pid(self) -> int:
        return self._popen.pid

    def is_alive(self) -> bool:
        return self._popen.poll() is None

    def terminate(self, *, timeout_seconds: float = 5.0) -> None:
        if not self.is_alive():
            return
        self._popen.send_signal(signal.SIGTERM)
        try:
            self._popen.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            self._popen.kill()
            self._popen.wait(timeout=timeout_seconds)


class SubprocessProcessRunner(ProcessRunner):
    """Real implementation — spawns the actual `llama-server` binary.

    Not exercised by the unit-test suite (would require the real binary);
    used only by manual/integration testing and eventual live deploy.
    """

    def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> ProcessHandle:
        popen = subprocess.Popen(  # noqa: S603 - binary path is operator/config-controlled, not request input
            [binary, *args],
            env=env or None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return SubprocessProcessHandle(popen)


__all__ = ["ProcessHandle", "ProcessRunner", "SubprocessProcessHandle", "SubprocessProcessRunner"]
