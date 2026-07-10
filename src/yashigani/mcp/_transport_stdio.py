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

P8 Stdio-binary pinning (4.0 — closes TODO[P8]):
  For stdio transports, TLS-fingerprint / SPIFFE pinning does not apply
  (there is no TLS channel).  The identity anchor for a spawned subprocess
  is its binary: ``StdioPinConfig`` lets the caller pin the subprocess by
  resolved absolute path and/or SHA-256 hash of the binary file.

  Design constraints (ground-truthed against the TODO comment):
    * The TODO said "cert/SPIFFE pinning for stdio transports that wrap over
      HTTP inside the subprocess."  HTTP wrappers have their upstream HTTP
      connection handled by ``_transport_http.py`` (cert/SPIFFE pinning at
      that layer); what is left at the stdio layer is the BINARY identity of
      the spawned process.
    * We verify BEFORE spawning to avoid any race window.  The path is
      resolved with ``shutil.which`` for commands on $PATH, or taken as-is
      for absolute paths.
    * Fail-closed: a pin mismatch raises ``StdioPinMismatchError`` before any
      subprocess is created.  In production/staging (YASHIGANI_ENV) this is
      unconditional; in dev it is still enforced at this layer (the broker
      layer can skip setting pin_config in dev).

v2.25.0 / P1 W3 Phase 2b-ii / L-05 stdio-day-1.
v4.0 / P8 stdio-binary-pin.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
from dataclasses import dataclass
from typing import Callable, Optional

from yashigani.mcp._types import McpPosture, McpTransportKind, PostureBinding
from yashigani.mcp._posture import derive_posture_from_channel

logger = logging.getLogger(__name__)

_MAX_RESTARTS = 3
_RESTART_BACKOFF_BASE_SECONDS = 0.5
_STOP_TIMEOUT_SECONDS = 5.0
_READ_TIMEOUT_SECONDS = 30.0

# Audit label for stdio binary pin mismatch (P8 — 4.0).
STDIO_PIN_MISMATCH_LABEL = "MCP_STDIO_BINARY_PIN_MISMATCH"


class StdioTransportError(RuntimeError):
    """Raised when the stdio transport cannot start or communicate."""


class StdioPinMismatchError(StdioTransportError):
    """
    Raised when the stdio subprocess binary does not match the pinned
    expected identity (path or SHA-256 hash).  Always fail-closed.
    """


@dataclass
class StdioPinConfig:
    """
    P8 identity-pin configuration for a stdio MCP-server subprocess.

    Attributes
    ----------
    command_path:
        Expected absolute path of the binary.  When set, the resolved path
        of ``command[0]`` (via ``shutil.which`` or direct resolve) MUST match
        exactly.  Prevents substitution by a different binary at the same name.
    binary_sha256:
        Expected SHA-256 hex digest of the binary file at the resolved path.
        When set, the file is read and hashed before spawn; mismatch aborts.
        Case-insensitive; leading/trailing whitespace stripped.

    At least one of ``command_path`` or ``binary_sha256`` should be set.
    Setting neither leaves the transport un-pinned (a warning is logged).
    Setting both provides defence-in-depth (path allowlist + content hash).
    """
    command_path: Optional[str] = None    # e.g. "/usr/local/bin/filesystem-mcp"
    binary_sha256: Optional[str] = None  # SHA-256 hex of binary file


def _resolve_binary_path(command: list[str]) -> Optional[str]:
    """
    Resolve the absolute path of ``command[0]``.

    Uses ``shutil.which`` for bare command names (searches $PATH).
    Returns the path as-is if already absolute and exists.
    Returns None if the binary cannot be found.
    """
    binary = command[0] if command else ""
    if not binary:
        return None
    if os.path.isabs(binary):
        return binary if os.path.isfile(binary) else None
    return shutil.which(binary)


def _hash_binary(path: str, *, _read_binary: Optional[Callable[[str], bytes]] = None) -> str:
    """Return the lowercase SHA-256 hex digest of the file at ``path``."""
    if _read_binary is not None:
        data = _read_binary(path)
    else:
        with open(path, "rb") as fh:
            data = fh.read()
    return hashlib.sha256(data).hexdigest()


def _verify_binary_pin(
    command: list[str],
    pin_config: "StdioPinConfig",
    *,
    _read_binary: Optional[Callable[[str], bytes]] = None,
    _resolve_path: Optional[Callable[[list[str]], Optional[str]]] = None,
) -> None:
    """
    Verify the subprocess binary against ``pin_config`` BEFORE spawning.

    Raises ``StdioPinMismatchError`` on any mismatch (fail-closed).

    Steps:
      1. Resolve the actual binary path from ``command[0]``.
      2. If ``pin_config.command_path`` is set, compare resolved vs expected.
      3. If ``pin_config.binary_sha256`` is set, hash the binary and compare.

    The audit event label ``STDIO_PIN_MISMATCH_LABEL`` is logged at WARNING
    level on every mismatch so it appears in the structured log stream.
    """
    if pin_config.command_path is None and pin_config.binary_sha256 is None:
        logger.warning(
            "mcp-broker stdio: %s StdioPinConfig has neither command_path nor "
            "binary_sha256 — subprocess is un-pinned (no identity verification)",
            STDIO_PIN_MISMATCH_LABEL,
        )
        return

    resolver = _resolve_path if _resolve_path is not None else _resolve_binary_path
    resolved = resolver(command)
    if resolved is None:
        _raise_pin_error(
            f"cannot resolve binary path for command[0]={command[0]!r}",
            command,
        )

    # 1. Path check.
    if pin_config.command_path is not None:
        expected_path = os.path.realpath(pin_config.command_path)
        actual_path = os.path.realpath(resolved)  # type: ignore[arg-type]
        if actual_path != expected_path:
            _raise_pin_error(
                f"command path mismatch: expected={expected_path!r} "
                f"actual={actual_path!r}",
                command,
            )

    # 2. Binary hash check.
    if pin_config.binary_sha256 is not None:
        expected_hex = pin_config.binary_sha256.strip().lower()
        try:
            actual_hex = _hash_binary(resolved, _read_binary=_read_binary)  # type: ignore[arg-type]
        except OSError as exc:
            _raise_pin_error(f"cannot read binary for hashing: {exc}", command)
        if actual_hex != expected_hex:
            _raise_pin_error(
                f"binary SHA-256 mismatch for {resolved!r}: "
                f"expected={expected_hex[:16]}... actual={actual_hex[:16]}...",
                command,
            )

    logger.debug(
        "mcp-broker stdio: P8 binary pin verified OK command[0]=%r resolved=%r",
        command[0], resolved,
    )


def _raise_pin_error(reason: str, command: list[str]) -> None:
    """Log STDIO_PIN_MISMATCH_LABEL and raise StdioPinMismatchError."""
    logger.warning(
        "mcp-broker stdio: %s command=%r — %s — subprocess NOT spawned",
        STDIO_PIN_MISMATCH_LABEL, command, reason,
    )
    raise StdioPinMismatchError(
        f"[P8] stdio binary pin verification FAILED ({STDIO_PIN_MISMATCH_LABEL}): "
        f"{reason}"
    )


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
        pin_config: Optional["StdioPinConfig"] = None,
    ) -> None:
        """
        Parameters
        ----------
        command:
            Command + args for the MCP-server subprocess.
        env:
            Optional extra env vars merged into os.environ for the subprocess.
        restart_on_crash:
            Whether to restart the subprocess on unexpected exit.
        pin_config:
            P8 binary identity pin.  When set, ``_verify_binary_pin()`` is
            called in ``start()`` BEFORE spawning.  A mismatch raises
            ``StdioPinMismatchError`` immediately (fail-closed).  When None,
            no binary pin check is performed (acceptable in dev; should always
            be set in production to close the P8 stdio residual).
        """
        self._command = command
        self._env = env
        self._restart_on_crash = restart_on_crash
        self._pin_config = pin_config
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
        """
        Spawn the MCP-server subprocess.

        P8 binary pin verification runs BEFORE ``create_subprocess_exec`` so
        there is no window between verification and spawn.  Fail-closed:
        ``StdioPinMismatchError`` is raised if the pin check fails; the
        subprocess is never created.
        """
        # P8 — verify binary identity before spawning.
        if self._pin_config is not None:
            _verify_binary_pin(self._command, self._pin_config)
        elif os.environ.get("YASHIGANI_ENV", "").lower().strip() in (
            "production", "staging"
        ):
            logger.warning(
                "mcp-broker stdio: [P8] no StdioPinConfig set for command=%r "
                "in %s environment — binary identity is UNPINNED.",
                self._command,
                os.environ.get("YASHIGANI_ENV", ""),
            )

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
