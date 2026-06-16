#!/usr/bin/env python3
"""
Yashigani sandboxed-extractor HTTP SERVER — runs INSIDE the long-lived extractor container.

DESIGN (LAURA-30-001 / YSG-RISK-080 fix — Design A):
  This server eliminates the host-escape primitive completely. Previously the extractor
  sandbox spawned ephemeral containers per job, requiring backoffice to reach the Docker
  socket (even through a socket-proxy). The tecnativa proxy is path/method-only — it
  cannot inspect the POST /containers/create BODY, so allowing CONTAINERS+POST=1
  was equivalent to arbitrary host bind-mount = full host takeover.

  Design A replaces this with a pre-spawned, long-running, hardened extractor service.
  Backoffice sends document bytes over HTTP to THIS server. THIS server calls the
  worker logic in a subprocess. The result is returned as JSON over HTTP.

  A compromised backoffice then has only one capability: POST a document to
  http://extractor-svc:8090/run — NO container API, NO host filesystem access,
  NO ability to create privileged containers or read /run/secrets of other services.

SECURITY POSTURE of this container (set by compose + Dockerfile):
  - egress=none: internal-only bridge (extractor_svc), no internet reachability
  - read-only rootfs (compose read_only: true)
  - all caps dropped (cap_drop: [ALL])
  - non-root (UID/GID 65532)
  - no-new-privileges
  - seccomp (docker/seccomp/yashigani-extractor.json)
  - AppArmor (yashigani-extractor where loaded)
  - mem_limit + pids_limit

CONTRACT (HTTP API):
  POST /run
    Request:  JSON {"data_b64": "<base64>", "job": "extract|redact|pseudonymize",
                    "fmt": "docx|xlsx|pptx|pdf|txt|csv",
                    "declared_mime": "<mime>", "plan_b64": "<base64 or ''>"}
    Response: 200 JSON (SandboxJobResult schema — same as worker stdout)
              400 JSON {"ok": false, "reason": "..."} on parse/validation error
              500 JSON {"ok": false, "reason": "..."} on worker crash

  GET /healthz
    Response: 200 "ok\n" when server is up and worker module is importable

  GET /_ping
    Response: 200 "pong\n"

WORKER INVOCATION:
  Each job is dispatched to a subprocess running worker.py (python /app/worker.py).
  The subprocess receives document bytes on stdin and writes one JSON object to stdout.
  This preserves the original worker isolation model (the parsing happens in a child
  process; a parser crash does not take down the server).

CONCURRENCY:
  Single-threaded HTTP server (stdlib BaseHTTPRequestHandler). Document processing is
  sequential — one job per request. Under backoffice load the operator can scale
  extractor replicas horizontally (compose scale); each replica handles one job at a time.
  This is appropriate for the demo / SMB tier; enterprise multi-tenant scale is a 3.x
  workstream.
"""
from __future__ import annotations

import base64
import http.server
import json
import logging
import os
import subprocess
import sys
import threading

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("extractor-server")

_WORKER_PATH = os.environ.get("YASHIGANI_WORKER_PATH", "/app/worker.py")
_TIMEOUT_S = int(os.environ.get("YASHIGANI_EXTRACTOR_TIMEOUT_S", "20"))
_MAX_REQUEST_BYTES = int(os.environ.get("YASHIGANI_EXTRACTOR_MAX_REQUEST_BYTES",
                                        str(128 * 1024 * 1024)))  # 128 MiB
_MAX_OUTPUT_BYTES = int(os.environ.get("YASHIGANI_EXTRACTOR_MAX_OUTPUT_BYTES",
                                       str(32 * 1024 * 1024)))  # 32 MiB

# Serialise concurrent requests — one job at a time per worker instance.
# A compromised backoffice can saturate this with requests but cannot escape
# the container. Rate-limiting is a 3.x concern (backoffice is admin-gated).
_JOB_LOCK = threading.Lock()


class ExtractorHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP request handler for the extractor service."""

    # Suppress the default request-per-line log in favour of structured logging.
    def log_request(self, code="-", size="-"):
        logger.info("HTTP %s %s → %s", self.command, self.path, code)

    def log_error(self, fmt, *args):
        logger.error("HTTP error: " + fmt, *args)

    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Defence-in-depth: no caching, no content sniffing.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/healthz", "/healthz/"):
            # Confirm the worker module is importable (a broken image would fail here).
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("worker", _WORKER_PATH)
                assert spec is not None
            except Exception as exc:
                self._send_json(503, {"ok": False, "reason": f"worker not importable: {exc}"})
                return
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/_ping", "/_ping/"):
            body = b"pong\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(404, {"ok": False, "reason": "not found"})

    def do_POST(self):
        if self.path not in ("/run", "/run/"):
            self._send_json(404, {"ok": False, "reason": "not found"})
            return

        # --- read + validate the request body ---
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_json(400, {"ok": False, "reason": "invalid Content-Length"})
            return

        if content_length > _MAX_REQUEST_BYTES:
            self._send_json(413, {
                "ok": False,
                "reason": f"request body {content_length} bytes exceeds cap {_MAX_REQUEST_BYTES}",
            })
            return

        raw = self.rfile.read(content_length)
        try:
            req = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._send_json(400, {"ok": False, "reason": f"invalid JSON: {exc}"})
            return

        if not isinstance(req, dict):
            self._send_json(400, {"ok": False, "reason": "request body must be a JSON object"})
            return

        data_b64 = req.get("data_b64", "")
        job = str(req.get("job", "extract"))
        fmt = str(req.get("fmt", ""))
        declared_mime = str(req.get("declared_mime", ""))
        plan_b64 = str(req.get("plan_b64", ""))

        if not fmt:
            self._send_json(400, {"ok": False, "reason": "missing 'fmt' field"})
            return
        if job not in ("extract", "redact", "pseudonymize"):
            self._send_json(400, {"ok": False, "reason": f"invalid job '{job}'"})
            return

        try:
            doc_bytes = base64.b64decode(data_b64)
        except Exception as exc:
            self._send_json(400, {"ok": False, "reason": f"data_b64 decode error: {exc}"})
            return

        # --- dispatch to worker subprocess (serialised) ---
        with _JOB_LOCK:
            result = _run_worker(
                doc_bytes=doc_bytes,
                job=job,
                fmt=fmt,
                declared_mime=declared_mime,
                plan_b64=plan_b64,
            )

        self._send_json(result["_status"], result["body"])

    # Disable keep-alive: each request is independent; the client (backoffice)
    # opens a fresh connection per job. Simpler and avoids connection state issues
    # in the single-threaded server.
    protocol_version = "HTTP/1.0"


def _run_worker(
    *,
    doc_bytes: bytes,
    job: str,
    fmt: str,
    declared_mime: str,
    plan_b64: str,
) -> dict:
    """Invoke worker.py in a subprocess. Returns dict with _status + body."""
    argv = [
        sys.executable, _WORKER_PATH,
        "--job", job,
        "--format", fmt,
        "--declared-mime", declared_mime or "",
    ]
    if job in ("redact", "pseudonymize") and plan_b64:
        argv += ["--plan", plan_b64]

    logger.info("dispatching worker: job=%s fmt=%s len=%d", job, fmt, len(doc_bytes))

    try:
        proc = subprocess.run(
            argv,
            input=doc_bytes,
            capture_output=True,
            timeout=_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("worker timeout after %ds (job=%s fmt=%s)", _TIMEOUT_S, job, fmt)
        stdout = exc.stdout or b""
        return {
            "_status": 200,
            "body": {
                "ok": False,
                "reason": f"worker killed (timeout {_TIMEOUT_S}s) — fail-closed BLOCK",
            },
        }
    except Exception as exc:
        logger.error("worker subprocess failed to start: %s", exc)
        return {
            "_status": 500,
            "body": {"ok": False, "reason": f"worker subprocess failed: {exc!r}"},
        }

    stderr_text = (proc.stderr or b"").decode("utf-8", "replace")
    if proc.returncode != 0:
        logger.warning(
            "worker exited %d (job=%s fmt=%s) stderr=%r",
            proc.returncode, job, fmt, stderr_text[:500],
        )
        return {
            "_status": 200,
            "body": {
                "ok": False,
                "reason": (
                    f"worker exited {proc.returncode} (parser crash/guard-abort) "
                    f"— fail-closed BLOCK"
                ),
            },
        }

    stdout = proc.stdout or b""
    if len(stdout) > _MAX_OUTPUT_BYTES:
        logger.warning(
            "worker output %d bytes exceeds cap %d (job=%s fmt=%s)",
            len(stdout), _MAX_OUTPUT_BYTES, job, fmt,
        )
        return {
            "_status": 200,
            "body": {
                "ok": False,
                "reason": (
                    f"worker output {len(stdout)} bytes exceeds cap {_MAX_OUTPUT_BYTES} "
                    f"— output-amplification, fail-closed"
                ),
            },
        }

    try:
        result_obj = json.loads(stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        logger.error("worker emitted non-JSON stdout (job=%s fmt=%s): %s", job, fmt, exc)
        return {
            "_status": 200,
            "body": {"ok": False, "reason": f"worker emitted non-JSON: {exc} — fail-closed"},
        }

    if not isinstance(result_obj, dict):
        return {
            "_status": 200,
            "body": {"ok": False, "reason": "worker result was not a JSON object — fail-closed"},
        }

    logger.info("worker completed: job=%s fmt=%s ok=%s", job, fmt, result_obj.get("ok"))
    return {"_status": 200, "body": result_obj}


def main() -> None:
    host = os.environ.get("YASHIGANI_EXTRACTOR_HOST", "0.0.0.0")
    port = int(os.environ.get("YASHIGANI_EXTRACTOR_PORT", "8090"))

    logger.info(
        "Yashigani extractor-server starting on %s:%d "
        "(worker=%s timeout=%ds max_request=%d max_output=%d)",
        host, port, _WORKER_PATH, _TIMEOUT_S, _MAX_REQUEST_BYTES, _MAX_OUTPUT_BYTES,
    )
    httpd = http.server.HTTPServer((host, port), ExtractorHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("extractor-server shutting down")
        httpd.server_close()


if __name__ == "__main__":
    main()
