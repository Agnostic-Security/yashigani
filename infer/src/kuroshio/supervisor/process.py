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
        # YSG-RISK-295: stdout/stderr must NOT be PIPE. Nothing in this package
        # ever reads those pipes, so once llama-server's output exceeds the OS
        # pipe buffer (~64KiB on both Linux and Darwin) the child blocks forever
        # on its next write. llama-server logs per-request slot/timing lines to
        # stderr continuously, so that is the steady state, not an edge case —
        # and `is_alive()` (Popen.poll()) still reports True for a process wedged
        # on write, so `healthz` would report healthy indefinitely.
        #
        # DEVNULL loses nothing that was previously kept: the PIPE contents were
        # never read by any code path. It is a deadlock fix, not an observability
        # regression. A container recycled every few hours masked this; a macOS
        # LaunchAgent with weeks of uptime will not.
        popen = subprocess.Popen(  # noqa: S603 - binary path is operator/config-controlled, not request input
            [binary, *args],
            env=env or None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return SubprocessProcessHandle(popen)


class DeviceProbe:
    """Ask a llama-server binary which compute devices it can actually see.

    YSG-RISK-301. `healthz` derived `gpu_engaged` from `n_gpu_layers` — the
    value we PASSED to llama-server, never a value read back — so a host with
    no GPU, or a binary built without the backend, ran on CPU and reported
    `gpu_engaged: true, healthy`. CPU-only inference is not a viable
    deployment, so that is not a slow deployment, it is a dead one showing
    green.

    `--list-devices` is the only device signal llama-server exposes: its HTTP
    API carries none (verified against `get_res_props()` in
    tools/server/server-context.cpp at the pinned tag — no n_gpu_layers, no
    device, no backend). So the probe runs the binary once, before serving.

    Injectable like ProcessRunner so unit tests never need a real binary.
    """

    def list_devices(self, binary: str) -> list[str]:
        raise NotImplementedError


class SubprocessDeviceProbe(DeviceProbe):
    """Real implementation — runs `llama-server --list-devices` once."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        self._timeout = timeout_seconds

    def list_devices(self, binary: str) -> list[str]:
        try:
            out = subprocess.run(  # noqa: S603 - operator/config-controlled path
                [binary, "--list-devices"],
                capture_output=True, text=True, timeout=self._timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            # Cannot determine -> report nothing seen. The caller fails closed;
            # an unreadable probe must never be read as "GPU present".
            return []
        names: list[str] = []
        for line in (out.stdout or "") .splitlines() + (out.stderr or "").splitlines():
            stripped = line.strip()
            # Device lines look like "MTL0: Apple M4 (16384 MiB, 16383 MiB free)"
            if ":" in stripped and not stripped.lower().startswith("available"):
                head = stripped.split(":", 1)[0].strip()
                if head and " " not in head:
                    names.append(head)
        return names


# Device-name prefixes that mean a real accelerator rather than the CPU/BLAS
# fallback. Measured on an M4: `--list-devices` prints "MTL0: Apple M4" for
# Metal and "BLAS: Accelerate" for the CPU-side fallback — BLAS is NOT an
# accelerator for our purposes and must not satisfy an expect_gpu deployment.
ACCELERATOR_PREFIXES = ("MTL", "CUDA", "ROCM", "HIP", "Vulkan", "VK", "SYCL", "CANN", "OPENCL")


def is_accelerator(device_name: str) -> bool:
    n = device_name.strip().upper()
    return any(n.startswith(p.upper()) for p in ACCELERATOR_PREFIXES)


__all__ = [
    "ACCELERATOR_PREFIXES",
    "DeviceProbe",
    "ProcessHandle",
    "ProcessRunner",
    "SubprocessDeviceProbe",
    "SubprocessProcessHandle",
    "SubprocessProcessRunner",
    "is_accelerator",
]
