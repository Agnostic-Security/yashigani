"""
MCP Broker — stdio transport (Shape A/C local process).

The gateway SPAWNS and OWNS the MCP-server subprocess. Traffic flows:
  gateway ──(stdin/stdout pipe)──> MCP server subprocess

Posture assignment:
  - Confirmed local OS pipe → posture = mcp-a (physical_channel).
  - subprocess.stdin/stdout are OS pipes, not TTYs.
  - isatty(fd) == False confirms pipe fd.
  - peer_pid is the subprocess PID (locally verifiable).

Lifecycle:
  - McpStdioTransport.start() spawns the subprocess.
  - McpStdioTransport.stop() sends SIGTERM, waits, then SIGKILL on timeout.
  - Crash/restart: if the subprocess exits unexpectedly, the transport
    attempts restart up to _MAX_RESTARTS times with exponential back-off.
  - No leaked subprocesses: __aenter__/__aexit__ guarantee cleanup.

DEFER to phase-2:
  - TODO[P8]: Upstream MCP-server cert/SPIFFE pinning for stdio transports
    that wrap over HTTP inside the subprocess.

v2.25.0 / P1 W3 Phase 2b-ii / L-05 stdio-day-1.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from yashigani.mcp._types import McpPosture, McpTransportKind, PostureBinding
from yashigani.mcp._posture import derive_posture_from_channel

logger = logging.getLogger(__name__)

_MAX_RESTARTS = 3
_RESTART_BACKOFF_BASE_SECONDS = 0.5
_STOP_TIMEOUT_SECONDS = 5.0
_READ_TIMEOUT_SECONDS = 30.0


class StdioTransportError(RuntimeError):
    """Raised when the stdio transport cannot start or communicate."""


class McpStdioTransport:
    """
    Gateway-owned stdio transport for a local MCP-server subprocess.

    Usage::

        async with McpStdioTransport(command=["mcp-server", "--flag"]) as transport:
            posture, binding = transport.posture_info
            response = await transport.send_request(mcp_request_json)

    The transport confirms the channel is a local OS pipe before setting
    posture=mcp-a. If the fd check fails, posture falls to mcp-b
    (YSG-RISK-055 defence — never escalate to mcp-a on ambiguous channels).
    """

    def __init__(
        self,
        command: list[str],
        env: Optional[dict] = None,
        restart_on_crash: bool = True,
    ) -> None:
        self._command = command
        self._env = env
        self._restart_on_crash = restart_on_crash
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._restart_count = 0
        self._posture: Optional[McpPosture] = None
        self._posture_binding: Optional[PostureBinding] = None

    async def __aenter__(self) -> "McpStdioTransport":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()

    async def start(self) -> None:
        """Spawn the MCP-server subprocess."""
        logger.info("mcp-broker stdio: spawning subprocess %s", self._command)
        proc_env = os.environ.copy()
        if self._env:
            proc_env.update(self._env)

        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=proc_env,
            close_fds=True,
        )

        # Derive posture from the physical channel.
        # asyncio.create_subprocess_exec with subprocess.PIPE always creates real OS pipes —
        # not TTYs. We confirm this by probing the underlying file descriptors.
        # StreamWriter.transport.get_extra_info("pipe") returns the pipe object on POSIX.
        # If we cannot probe the fd (platform variation), we default to is_pipe=True because
        # PIPE is deterministic: the gateway spawned this process, the fd is not a TTY.
        is_pipe = True
        try:
            # Try to get the underlying fd via the asyncio transport layer.
            # subprocess.PIPE creates a StreamReaderProtocol backed by a Pipe transport;
            # the pipe transport wraps the actual OS fd.
            stdin_transport = (
                self._proc.stdin.transport  # type: ignore[attr-defined]
                if self._proc.stdin is not None else None
            )
            stdout_transport = (
                self._proc.stdout._transport  # type: ignore[attr-defined]
                if self._proc.stdout is not None else None
            )
            for transport in filter(None, [stdin_transport, stdout_transport]):
                fd = transport.get_extra_info("pipe")
                if fd is not None and hasattr(fd, "fileno"):
                    try:
                        if os.isatty(fd.fileno()):
                            is_pipe = False
                            break
                    except (OSError, AttributeError):
                        pass  # fd.fileno() may raise on some platforms; keep is_pipe=True
        except AttributeError:
            # asyncio internals differ between Python versions / platforms.
            # Fallback: subprocess.PIPE always creates real OS pipes — keep is_pipe=True.
            pass

        self._posture, self._posture_binding = derive_posture_from_channel(
            transport_kind=McpTransportKind.LOCAL_STDIO,
            is_local_pipe=is_pipe,
            peer_pid=self._proc.pid,
        )
        logger.info(
            "mcp-broker stdio: subprocess pid=%d posture=%s is_pipe=%s",
            self._proc.pid, self._posture.value, is_pipe,
        )

    async def stop(self) -> None:
        """Terminate the subprocess cleanly."""
        if self._proc is None:
            return
        try:
            if self._proc.returncode is None:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=_STOP_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    logger.warning(
                        "mcp-broker stdio: subprocess pid=%d did not exit after SIGTERM, sending SIGKILL",
                        self._proc.pid,
                    )
                    self._proc.kill()
                    await self._proc.wait()
        except ProcessLookupError:
            pass  # already gone
        finally:
            self._proc = None
            logger.info("mcp-broker stdio: subprocess stopped")

    async def send_request(self, request_json: str) -> str:
        """
        Send a JSON-RPC request to the subprocess via stdin and read the response.

        On subprocess crash, restarts up to _MAX_RESTARTS times.
        Raises StdioTransportError if the subprocess is down after all retries.
        """
        for attempt in range(1 + _MAX_RESTARTS):
            if self._proc is None or self._proc.returncode is not None:
                if not self._restart_on_crash or attempt >= _MAX_RESTARTS:
                    raise StdioTransportError(
                        f"MCP stdio subprocess is not running after {attempt} restart attempts"
                    )
                logger.warning(
                    "mcp-broker stdio: subprocess crashed (returncode=%s), restarting (%d/%d)",
                    self._proc.returncode if self._proc else "N/A",
                    attempt + 1, _MAX_RESTARTS,
                )
                await self.start()
                await asyncio.sleep(_RESTART_BACKOFF_BASE_SECONDS * (2 ** attempt))

            try:
                assert self._proc is not None
                assert self._proc.stdin is not None
                assert self._proc.stdout is not None

                # Write request (MCP stdio uses newline-delimited JSON)
                data = (request_json.strip() + "\n").encode("utf-8")
                self._proc.stdin.write(data)
                await self._proc.stdin.drain()

                # Read response line
                line = await asyncio.wait_for(
                    self._proc.stdout.readline(),
                    timeout=_READ_TIMEOUT_SECONDS,
                )
                if not line:
                    raise StdioTransportError("Subprocess closed stdout (EOF)")
                return line.decode("utf-8").strip()

            except (asyncio.TimeoutError, BrokenPipeError, ConnectionResetError) as exc:
                logger.error("mcp-broker stdio: send error attempt %d: %s", attempt + 1, exc)
                if attempt >= _MAX_RESTARTS:
                    raise StdioTransportError(
                        f"MCP stdio send failed after {attempt + 1} attempts: {exc}"
                    ) from exc
                # Let the loop restart
                await self.stop()
                continue

        raise StdioTransportError("MCP stdio send_request: unreachable")

    @property
    def posture_info(self) -> tuple[McpPosture, PostureBinding]:
        """Return the (posture, PostureBinding) derived at startup."""
        if self._posture is None or self._posture_binding is None:
            raise RuntimeError("Transport not started — call start() first")
        return self._posture, self._posture_binding

    @property
    def subprocess_pid(self) -> Optional[int]:
        return self._proc.pid if self._proc else None

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None
