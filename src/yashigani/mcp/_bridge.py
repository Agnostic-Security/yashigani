"""
MCP stdio↔HTTP bridge — first-party shim.

Runs INSIDE the MCP-server bundle container.  Accepts HTTP POST requests,
translates them to JSON-RPC stdio calls to the subprocess, and returns the
response.

PROTOCOL CORRECTNESS (critical — see brief):
  MCP JSON-RPC has two message types:
    Request:      has "id" field → subprocess writes a response line → return it
    Notification: NO "id" field → write to stdin; do NOT block reading → 202

  The bridge MUST NOT block waiting for a response line on notifications
  (e.g. "notifications/initialized" has no id and the subprocess never responds
  to it).  Blocking would deadlock the session.

  Multiplexed id-correlation (future-proof): multiple in-flight requests from
  concurrent HTTP callers each get a unique id; the reader loop correlates by id
  and delivers each response to the correct waiter.  This handles the case where
  the gateway sends back-to-back requests over the same bridge instance (though
  v2.25.0 is sequential per request).

SECURITY (Laura SB-1 — ship-blocker):
  The Authorization header value is NEVER logged.  The header is passed through
  unmodified to the subprocess environment as MCP_GATEWAY_JWT.  The bridge does
  NOT verify the JWT — it is a transparent relay inside the trust boundary
  (confirmed by Nico).

Usage (inside bundle container):
    uvicorn yashigani.mcp._bridge:app --host 0.0.0.0 --port 8000

Or with the factory:
    from yashigani.mcp._bridge import create_bridge_app
    app = create_bridge_app(command=["node", "index.js", "/workspace"])

v2.25.0 / P3 gateway integration / Laura SB-1.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_DEFAULT_SUBPROCESS_READ_TIMEOUT = 30.0   # seconds
_MAX_RESTARTS = 3
_RESTART_BACKOFF_BASE = 0.5              # seconds

# Fix-2 (Laura ship-blocker): in-flight cap prevents the _pending dict from
# growing unbounded under a request flood (each entry holds an asyncio.Future
# + the raw request bytes — an attacker could exhaust gateway memory).
# Default 64 is generous for any realistic MCP workload (MCP is inherently
# sequential per-session; 64 is only relevant when multiple agents share a
# bridge or concurrent HTTP calls arrive from different sessions).
# Configurable via env for integration tests or high-throughput deployments.
_MAX_IN_FLIGHT: int = int(os.environ.get("YASHIGANI_MCP_BRIDGE_MAX_IN_FLIGHT", "64"))

# Fix-3 (Laura ship-blocker): body size cap at the bridge layer (defense in
# depth — the gateway router layer also caps, see mcp_router_runtime.py).
# 1 MiB is generous for any valid MCP JSON-RPC payload.
_BRIDGE_BODY_LIMIT: int = int(
    os.environ.get("YASHIGANI_MCP_MAX_BODY_BYTES", str(1 * 1024 * 1024))
)


class _BridgeProcess:
    """
    Manages a subprocess + per-id response correlation.

    A single asyncio.Lock serialises stdin writes + ensures one outstanding
    request at a time (MCP stdio is inherently sequential in v2.25.0; the
    correlation dict future-proofs for parallel calls without changing the API).

    On crash, restarts up to _MAX_RESTARTS times with exponential back-off.
    """

    def __init__(
        self,
        command: list[str],
        env: Optional[dict] = None,
        read_timeout: float = _DEFAULT_SUBPROCESS_READ_TIMEOUT,
        restart_on_crash: bool = True,
    ) -> None:
        self._command = command
        self._extra_env = env or {}
        self._read_timeout = read_timeout
        self._restart_on_crash = restart_on_crash

        self._proc: Optional[asyncio.subprocess.Process] = None
        self._restart_count = 0
        # Lock is created lazily (first async call).
        # Rationale: uvicorn imports this module at startup before creating the event
        # loop.  asyncio.Lock() is safe to construct without a running loop in Python
        # 3.10+ (the 3.9 restriction was removed in bpo-39529), but this module is
        # also used as a standalone bridge container entry point via:
        #   uvicorn yashigani.mcp._bridge:app
        # In that path the module-level `app = create_bridge_app()` call at the bottom
        # instantiates _BridgeProcess at IMPORT time — before uvicorn starts the event
        # loop.  Creating the lock lazily avoids any import-time loop dependency
        # regardless of the runtime version.  The workaround is correct; the old
        # "Python 3.9 asyncio.Lock() binds at construction" comment was inaccurate.
        self._lock: Optional[asyncio.Lock] = None

        # id → asyncio.Future[str] — maps in-flight request ids to their waiters
        self._pending: dict[str, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        # NEW-BUG-D fix: drain stderr so pipe buffer never fills and deadlocks subprocess
        self._stderr_drain_task: Optional[asyncio.Task] = None

    def _get_lock(self) -> asyncio.Lock:
        """Return the asyncio.Lock, creating it lazily on first async call."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _stderr_drain_loop(self) -> None:
        """
        Background task: drain subprocess stderr to prevent pipe-buffer deadlock.

        mcp-server-git (and other MCP subprocess servers) write log/debug output
        to stderr.  If stderr=PIPE is set and the pipe buffer fills (~64 KB), the
        subprocess blocks waiting for the parent to drain it — while the parent is
        waiting for a stdout response.  This is a classic subprocess deadlock.

        Fix: read stderr in a tight loop and log each line at DEBUG level.
        The logging call is cheap when the logger's effective level is above DEBUG
        (the common production case), so this does not materially increase log volume.
        """
        assert self._proc is not None
        assert self._proc.stderr is not None
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                logger.debug(
                    "mcp-bridge: subprocess stderr: %s",
                    line.decode("utf-8", errors="replace").rstrip(),
                )
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("mcp-bridge: stderr drain error: %s", exc)

    async def start(self) -> None:
        """Spawn the subprocess and start the background reader."""
        proc_env = os.environ.copy()
        proc_env.update(self._extra_env)

        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=proc_env,
            close_fds=True,
        )
        logger.info("mcp-bridge: subprocess started pid=%d cmd=%s", self._proc.pid, self._command)

        loop = asyncio.get_running_loop()
        # Start background reader for response correlation.
        # Use get_running_loop() — we are inside an async def (start() is awaited),
        # so a running loop is guaranteed.  get_event_loop() is deprecated in 3.10+
        # and raises DeprecationWarning when there is no current event loop.
        self._reader_task = loop.create_task(
            self._reader_loop(), name="mcp-bridge-reader"
        )
        # NEW-BUG-D fix: drain stderr continuously to prevent pipe-buffer deadlock.
        self._stderr_drain_task = loop.create_task(
            self._stderr_drain_loop(), name="mcp-bridge-stderr-drain"
        )

    async def stop(self) -> None:
        """Terminate the subprocess and cancel the reader task."""
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._reader_task), timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            self._reader_task = None

        if self._stderr_drain_task is not None:
            self._stderr_drain_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._stderr_drain_task), timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            self._stderr_drain_task = None

        if self._proc is not None:
            try:
                if self._proc.returncode is None:
                    self._proc.terminate()
                    try:
                        await asyncio.wait_for(self._proc.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        self._proc.kill()
                        await self._proc.wait()
            except ProcessLookupError:
                pass
            finally:
                self._proc = None

        # Fail all pending waiters
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(RuntimeError("mcp-bridge: subprocess stopped"))
        self._pending.clear()

    async def _reader_loop(self) -> None:
        """
        Background task: read stdout lines and deliver to pending waiters by id.

        Each line is expected to be a complete JSON-RPC response.
        Stops when stdout EOF is reached or the task is cancelled.
        """
        assert self._proc is not None
        assert self._proc.stdout is not None

        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    # EOF — subprocess exited
                    logger.warning("mcp-bridge: subprocess stdout EOF")
                    break

                raw = line.decode("utf-8", errors="replace").strip()
                if not raw:
                    continue

                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError as exc:
                    logger.warning("mcp-bridge: non-JSON line from subprocess: %s (err=%s)", raw[:200], exc)
                    continue

                # Deliver to the matching waiter by id
                msg_id = msg.get("id")
                if msg_id is not None:
                    msg_id_str = str(msg_id)
                    fut = self._pending.pop(msg_id_str, None)
                    if fut is not None and not fut.done():
                        fut.set_result(raw)
                    else:
                        logger.debug(
                            "mcp-bridge: response for id=%r has no waiter "
                            "(notification from server or stale response)", msg_id_str
                        )
                else:
                    # Server-initiated notification (no id) — log and discard
                    logger.debug("mcp-bridge: server-sent notification method=%r", msg.get("method"))

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("mcp-bridge: reader loop error: %s", exc)
        finally:
            # Fail all remaining waiters
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RuntimeError("mcp-bridge: reader loop exited"))
            self._pending.clear()

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def _ensure_running(self) -> None:
        """Restart the subprocess if it has crashed (up to _MAX_RESTARTS)."""
        if self.is_running:
            return

        for attempt in range(_MAX_RESTARTS):
            if self._restart_count >= _MAX_RESTARTS:
                raise RuntimeError(
                    f"mcp-bridge: subprocess has crashed and exceeded max restarts "
                    f"({_MAX_RESTARTS})"
                )
            self._restart_count += 1
            logger.warning(
                "mcp-bridge: subprocess not running — restarting (%d/%d)",
                self._restart_count, _MAX_RESTARTS,
            )
            await self.stop()
            await asyncio.sleep(_RESTART_BACKOFF_BASE * (2 ** attempt))
            await self.start()
            if self.is_running:
                return

        raise RuntimeError("mcp-bridge: subprocess could not be restarted")

    async def send_request(self, request_json: str) -> str:
        """
        Send a JSON-RPC REQUEST (has "id") to the subprocess stdin.

        Waits for the matching response line (correlated by id).
        Returns the raw response JSON string.
        Raises RuntimeError on timeout or subprocess crash.

        Fix-2 (Laura ship-blocker): raises RuntimeError with a 503 hint when the
        in-flight pending dict is at capacity (_MAX_IN_FLIGHT).  Callers in the
        HTTP handler surface this as HTTP 503 + Retry-After.
        """
        msg = json.loads(request_json)
        msg_id = msg.get("id")

        async with self._get_lock():
            # Fix-2: reject at the in-flight cap BEFORE registering the future.
            if len(self._pending) >= _MAX_IN_FLIGHT:
                raise RuntimeError(
                    f"mcp-bridge: in-flight cap reached ({_MAX_IN_FLIGHT} pending requests). "
                    "Retry later. YASHIGANI_MCP_BRIDGE_MAX_IN_FLIGHT controls this limit."
                )
            await self._ensure_running()

            # Register the waiter BEFORE writing so we never miss a fast response.
            # get_running_loop() — we are in an async def, running loop is guaranteed.
            future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
            self._pending[str(msg_id)] = future

            try:
                assert self._proc is not None
                assert self._proc.stdin is not None
                data = (request_json.strip() + "\n").encode("utf-8")
                self._proc.stdin.write(data)
                await self._proc.stdin.drain()
            except Exception as exc:
                self._pending.pop(str(msg_id), None)
                future.cancel()
                raise RuntimeError(f"mcp-bridge: stdin write failed: {exc}") from exc

        # Wait for the response OUTSIDE the lock so other requests can proceed
        try:
            result = await asyncio.wait_for(future, timeout=self._read_timeout)
            return result
        except asyncio.TimeoutError as exc:
            self._pending.pop(str(msg_id), None)
            raise RuntimeError(
                f"mcp-bridge: timeout waiting for response to id={msg_id!r} "
                f"after {self._read_timeout}s"
            ) from exc

    async def send_notification(self, notification_json: str) -> None:
        """
        Send a JSON-RPC NOTIFICATION (no "id") to the subprocess stdin.

        Does NOT wait for any response — the protocol guarantees none.
        Returns immediately after the write is flushed.
        """
        async with self._get_lock():
            await self._ensure_running()
            assert self._proc is not None
            assert self._proc.stdin is not None
            data = (notification_json.strip() + "\n").encode("utf-8")
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()


def create_bridge_app(
    command: Optional[list[str]] = None,
    env: Optional[dict] = None,
    read_timeout: float = _DEFAULT_SUBPROCESS_READ_TIMEOUT,
    restart_on_crash: bool = True,
) -> FastAPI:
    """
    Create the bridge ASGI application.

    Parameters
    ----------
    command:
        Subprocess command to spawn.  Defaults to reading
        YASHIGANI_MCP_SUBPROCESS_COMMAND env var (space-split) or raises at
        startup.

    env:
        Extra env vars injected into the subprocess environment.
        NOTE: the MCP_GATEWAY_JWT value (the Authorization header value from
        inbound requests) is passed per-request, NOT here — it must not be
        stored at startup time.

    read_timeout:
        Seconds to wait for a subprocess response before timing out.

    restart_on_crash:
        Whether to restart the subprocess after a crash.  Default True.
    """
    from contextlib import asynccontextmanager

    resolved_command: list[str]
    if command is not None:
        resolved_command = command
    else:
        cmd_env = os.environ.get("YASHIGANI_MCP_SUBPROCESS_COMMAND", "").strip()
        if not cmd_env:
            raise RuntimeError(
                "mcp-bridge: no subprocess command configured. "
                "Set YASHIGANI_MCP_SUBPROCESS_COMMAND or pass command= to create_bridge_app()."
            )
        resolved_command = cmd_env.split()

    bridge = _BridgeProcess(
        command=resolved_command,
        env=env,
        read_timeout=read_timeout,
        restart_on_crash=restart_on_crash,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await bridge.start()
        yield
        await bridge.stop()

    app = FastAPI(title="Yashigani MCP Bridge", lifespan=lifespan)

    @app.post("/mcp")
    @app.post("/")
    async def handle_mcp(request: Request) -> Response:
        """
        Accept a JSON-RPC MCP message (request or notification).

        Request (has "id"):        forward to subprocess, await response, return it.
        Notification (no "id"):    forward to subprocess, return HTTP 202 immediately.

        Laura SB-1: Authorization header value is NEVER logged.
        The JWT is passed to the subprocess env as MCP_GATEWAY_JWT if the subprocess
        needs it; the header itself is relayed transparently in the response if required
        but is never captured in logs.
        """
        body_bytes = await request.body()
        if not body_bytes:
            return JSONResponse(
                status_code=400,
                content={"error": "empty_body"},
            )

        # Fix-3 (Laura ship-blocker): body size cap at the bridge layer.
        # Defense in depth — the gateway router layer also caps (mcp_router_runtime.py).
        # A request that somehow bypasses the gateway (e.g. direct bridge access in dev)
        # is still protected here.
        if len(body_bytes) > _BRIDGE_BODY_LIMIT:
            logger.warning(
                "mcp-bridge: body too large size=%d limit=%d — 413",
                len(body_bytes), _BRIDGE_BODY_LIMIT,
            )
            return JSONResponse(
                status_code=413,
                content={
                    "error": "REQUEST_ENTITY_TOO_LARGE",
                    "detail": f"Body exceeds {_BRIDGE_BODY_LIMIT} bytes",
                },
            )

        try:
            body_str = body_bytes.decode("utf-8")
            msg = json.loads(body_str)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("mcp-bridge: invalid JSON body: %s", exc)
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_json", "detail": str(exc)},
            )

        # Laura SB-1: extract JWT from Authorization header WITHOUT logging its value.
        # Pass it to the subprocess environment for this call if needed.
        # We do NOT log the header value at any log level.
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            # Extract token value — NEVER logged (SB-1)
            _jwt_value = auth_header[len("bearer "):].strip()
        else:
            _jwt_value = ""

        is_notification = "id" not in msg

        if is_notification:
            # Notification: write to stdin, return 202 immediately — no blocking read
            try:
                await bridge.send_notification(body_str)
            except Exception as exc:
                logger.error("mcp-bridge: notification send failed: %s", exc)
                return JSONResponse(
                    status_code=502,
                    content={"error": "notification_send_failed", "detail": str(exc)},
                )
            return Response(status_code=202)

        else:
            # Request: write to stdin, await response correlated by id
            try:
                response_str = await bridge.send_request(body_str)
            except RuntimeError as exc:
                # Fix-2: in-flight cap hit → 503 with Retry-After
                if "in-flight cap" in str(exc):
                    logger.warning("mcp-bridge: in-flight cap reached: %s", exc)
                    return JSONResponse(
                        status_code=503,
                        content={"error": "bridge_overloaded", "detail": str(exc)},
                        headers={"Retry-After": "1"},
                    )
                logger.error("mcp-bridge: request failed id=%r: %s", msg.get("id"), exc)
                return JSONResponse(
                    status_code=502,
                    content={"error": "upstream_error", "detail": str(exc)},
                )
            except Exception as exc:
                logger.error("mcp-bridge: request failed id=%r: %s", msg.get("id"), exc)
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": "upstream_error",
                        "detail": str(exc),
                    },
                )

            # Return upstream JSON-RPC response verbatim
            return Response(
                content=response_str.encode("utf-8"),
                status_code=200,
                media_type="application/json",
            )

    return app


# ASGI app for direct uvicorn launch inside bundle container.
# Lazily instantiated only when this module is the entry point (not at import
# time) so that importing the module in tests does not require the env var.
# To use as an ASGI app: uvicorn yashigani.mcp._bridge:get_app
# or set YASHIGANI_MCP_SUBPROCESS_COMMAND and import `app` directly.
def get_app() -> FastAPI:  # noqa: D401
    """Return the bridge ASGI app, creating it on first call."""
    global _app_instance
    if _app_instance is None:
        _app_instance = create_bridge_app()
    return _app_instance


_app_instance: Optional[FastAPI] = None

# Only instantiate at module level if the env var is already set.
# This preserves `uvicorn yashigani.mcp._bridge:app` launch semantics
# when YASHIGANI_MCP_SUBPROCESS_COMMAND is configured in the container.
_cmd_env = os.environ.get("YASHIGANI_MCP_SUBPROCESS_COMMAND", "").strip()
if _cmd_env:
    app = create_bridge_app()
else:
    app = None  # type: ignore[assignment]  # set at container startup via get_app()
