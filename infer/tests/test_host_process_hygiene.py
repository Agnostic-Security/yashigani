# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Regression tests for the host-process defects — YSG-RISK-295/297/298.

All three are latent in a container that gets recycled and become real on a
macOS LaunchAgent deploy with weeks of uptime (6.0). Each test here FAILS on
the pre-fix tree, which is the only reason it is worth having.
"""

from __future__ import annotations

import inspect
import socket
import subprocess
from pathlib import Path

import pytest

from kuroshio.adapters.convert import SubprocessConversionInvoker
from kuroshio.supervisor.process import SubprocessProcessRunner
from kuroshio.supervisor.supervisor import Supervisor

_COMMIT = "a" * 40


# --- YSG-RISK-295: stdout/stderr must not be an undrained PIPE --------------


def test_spawn_does_not_use_undrained_pipes() -> None:
    """A PIPE nothing ever reads deadlocks the child once the buffer fills.

    Nothing in this package reads those pipes, and `is_alive()` keeps
    reporting True for a process wedged on write, so `healthz` would report
    healthy forever. Asserted on the source because spawning a real
    llama-server is out of scope for the unit suite (conftest contract).
    """
    src = inspect.getsource(SubprocessProcessRunner.spawn)
    assert "subprocess.PIPE" not in src, (
        "llama-server stdout/stderr must not be PIPE — nothing drains them, so "
        "the child blocks on write once the OS pipe buffer fills (YSG-RISK-295)"
    )
    assert src.count("subprocess.DEVNULL") == 2, (
        "both stdout and stderr must be explicitly redirected, not left to inherit"
    )


# --- YSG-RISK-298: port allocation must probe, not count -------------------


def test_default_port_allocator_skips_a_port_already_held_by_another_process() -> None:
    """The discriminating case: something else on the host holds the port the
    old counter would have handed out (39000, its fixed base). A probing
    allocator must route around it; a counter hands out the occupied port.
    """
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            squatter.bind(("127.0.0.1", 39000))
        except OSError:  # pragma: no cover - port genuinely unavailable on this host
            pytest.skip("port 39000 not bindable on this host; cannot stage the collision")
        squatter.listen(1)

        supervisor = Supervisor(process_runner=_NullRunner(), llama_server_binary="x")
        port = supervisor._default_port_allocator()  # noqa: SLF001 - testing the default directly

        assert port != 39000, (
            "allocator handed out a port another process already holds — the "
            "sequential-counter failure mode on a shared host (YSG-RISK-298)"
        )
        assert 1024 < port <= 65535
        # Prove it is genuinely free right now, not merely different.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
            check.bind(("127.0.0.1", port))
    finally:
        squatter.close()


def test_two_supervisors_do_not_collide_on_a_shared_host() -> None:
    """The Mac case: two engine roles in one port space, not one netns each."""
    a = Supervisor(process_runner=_NullRunner(), llama_server_binary="x")
    b = Supervisor(process_runner=_NullRunner(), llama_server_binary="x")
    # Hold each port open so the second supervisor cannot be handed the same one.
    held = []
    try:
        for sup in (a, b):
            p = sup._default_port_allocator()  # noqa: SLF001
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", p))
            held.append((p, s))
        assert held[0][0] != held[1][0], (
            "two supervisors on one host were handed the same port — the "
            "sequential-counter allocator's failure mode (YSG-RISK-298)"
        )
    finally:
        for _, s in held:
            s.close()


# --- YSG-RISK-297: conversion PATH must be injectable, not hardcoded -------


def _invoker(**kw: object) -> SubprocessConversionInvoker:
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    inv = SubprocessConversionInvoker(
        convert_script=Path("/tmp/convert.py"),
        quantize_binary=Path("/tmp/llama-quantize"),
        tool_commit=_COMMIT,
        run=fake_run,
        **kw,  # type: ignore[arg-type]
    )
    inv._captured = captured  # type: ignore[attr-defined]
    return inv


def test_conversion_path_defaults_to_the_restricted_linux_set() -> None:
    inv = _invoker()
    inv._run_step(["/bin/true"], step="convert", cwd=Path("/tmp"))  # noqa: SLF001
    env = inv._captured["env"]  # type: ignore[attr-defined]
    assert env["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert env["HF_HUB_OFFLINE"] == "1"


def test_conversion_path_is_injectable_for_apple_silicon() -> None:
    """The Mac toolchain lives in /opt/homebrew/bin, which the old literal missed."""
    inv = _invoker(path_dirs=("/opt/homebrew/bin", "/usr/bin", "/bin"))
    inv._run_step(["/bin/true"], step="convert", cwd=Path("/tmp"))  # noqa: SLF001
    env = inv._captured["env"]  # type: ignore[attr-defined]
    assert env["PATH"] == "/opt/homebrew/bin:/usr/bin:/bin"
    # Still restricted — not inherited wholesale from os.environ.
    assert env["TRANSFORMERS_OFFLINE"] == "1"


def test_conversion_refuses_an_empty_path() -> None:
    with pytest.raises(ValueError, match="path_dirs must not be empty"):
        _invoker(path_dirs=())


class _NullRunner:
    def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> object:
        raise AssertionError("not spawned in these tests")
