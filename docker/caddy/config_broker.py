#!/usr/bin/env python3
"""
Yashigani Caddy config-validating broker — FINDING-V412-CADDYADMIN-001 (R1 + R2).

THREAT MODEL (compromised backoffice, per Laura's live PoC —
laura-012-reattack-fixed.md, LAURA-V412-CADDYADMIN-001):

  R1 — even through the narrowed POST-/load-only Caddy relay (see
       docker/Caddyfile.{acme,selfsigned,ca} "MCP-onboarding reload relay"),
       the POSTed Caddyfile BODY can still define a rogue inline CA / TLS
       client-auth trust anchor / new listener. Pure Caddyfile routing
       (method+path matchers) cannot inspect request-body CONTENT — Caddy has
       no core directive for that.

  R2 — backoffice legitimately WRITES agent-onboarding Caddy snippets to
       docker/caddy/agents/*.caddy (mcp_onboard.py step 3, codegen.py
       approve_mcp_onboard). That directory (and, it turns out, the OTHER
       snippet files the base Caddyfile imports — Caddyfile.csp,
       Caddyfile.ollama-front, Caddyfile.openclaw-egress,
       Caddyfile.openclaw-webhooks) are NOT RO-shadowed against backoffice's
       `./:/mnt/install/docker:rw` mount (only secrets/secrets-caddy/var/.env/
       the active-mode Caddyfile are shadowed, per FINDING-LIC-012). A
       compromised backoffice can drop/rewrite ANY of these files with a
       rogue construct; the `import /etc/caddy/agents/*.caddy` sentinel is
       resolved at Caddyfile TOP LEVEL — full server-block scope, identical
       blast radius to Laura's admin-socket PoC — and takes effect on the
       NEXT reload, with zero admin-API interaction at all.

DESIGN — validate the FULLY ASSEMBLED OUTPUT, not each input surface
separately:

  Caddy resolves `import` directives (agents/*.caddy AND the four snippet
  files above) INTO one merged config at adapt/load time — R1 and R2 are the
  SAME class of problem (backoffice-influenced content reaching Caddy's trust
  decisions) manifesting via two different write paths (an HTTP body vs a
  filesystem write). This broker owns the single trust decision Caddy makes
  when it reloads: it runs `caddy adapt` on the SUBMITTED body EXACTLY as
  Caddy itself would (same absolute import paths, same live-mounted
  /etc/caddy/agents + snippet files) to get the config Caddy would ACTUALLY
  load, then checks the trust-critical subset of that merged output against a
  pinned baseline — REGARDLESS of which imported file introduced a change.

  BASELINE IMMUNITY (the reason this isn't circular): if the baseline were
  recomputed from the SAME live, backoffice-reachable files at request time,
  a compromised backoffice could poison BOTH sides of the comparison
  (baseline and candidate) identically and the diff would show nothing. The
  baseline is instead PRE-COMPUTED AT IMAGE BUILD TIME from the repo source
  (see docker/caddy/Dockerfile.caddy-broker "baseline" stage) — adapted with
  an EMPTY agents directory and using the build context's own copies of the
  four snippet files, then baked into the image as adapted-<mode>.json. At
  runtime this broker only ever LOADS that baked JSON (never re-derives it
  from a live mount) and extracts its invariants once at startup. No request
  handler, however compromised its caller, can move the baseline.

INVARIANTS CHECKED (candidate vs. baked baseline — see _extract_invariants):
  - `admin` (the global admin-API directive) must be byte-identical to the
    baseline. Blocks re-pointing/re-widening the admin socket itself.
  - No `apps.pki` key anywhere (Caddy's internal-CA management app — an
    attacker-installed PKI app could mint/trust arbitrary certs).
  - `apps.tls.automation` (issuer modules — ACME/internal cert issuance) and
    `apps.tls.certificates` (Caddy's OWN server leaf cert/key paths) must be
    byte-identical to the baseline. Blocks issuer/leaf-cert hijacking.
  - Every server's `listen` addresses must be a SUBSET of the baseline's
    listen-address union. Blocks Laura's exact PoC pattern (a brand-new
    isolated listener) AND any new listener introduced via a rogue agent
    snippet — legitimate agent snippets (codegen.py _gen_caddy_snippet)
    NEVER declare a new listener; they only attach routes to the existing
    `:443` site.
  - Every `{"ca": {...}}` trust-anchor reference found ANYWHERE in the
    merged config (recursive walk — covers `client_authentication.ca` at any
    nesting depth) must use `provider: file` (never `inline`) and its
    `pem_files` must be a subset of the baseline's own CA file paths. Blocks
    Laura's exact exploit (an inline rogue CA as a trust anchor) and any
    attempt to widen client-cert trust to an unexpected file.
  - No `"provider": "inline"` anywhere in the tree at all (belt-and-braces —
    covers inline leaf certs too, not just CA trust pools).

ENDPOINT:
  POST /load   Content-Type: text/caddyfile (or any — not inspected).
               Body = candidate Caddyfile text (same contract
               mcp_onboard.py's default_caddy_reloader() already uses).
               On PASS: forwarded verbatim to the real (private) admin
               socket's own /load; the real admin API's response/status is
               relayed back unchanged.
               On FAIL: 422, reason in the body, real admin socket is NEVER
               contacted (fail-closed — same "first non-2xx is FAIL, no
               downgrade" discipline as every other Yashigani gate).
  GET  /healthz  200 "ok" once the baseline loaded successfully at startup.

This process has NO access to /run/secrets (caddy adapt does not need cert
files to exist — validated live; only `caddy validate` provisions modules and
opens certs). Its blast radius if compromised: it can reach the real admin
socket ONLY via the same /load contract it itself enforces on inbound
requests — it holds no other capability, no other mount, no other secret.
"""
from __future__ import annotations

import http.client
import http.server
import json
import logging
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s caddy-config-broker: %(message)s",
)
logger = logging.getLogger("caddy-config-broker")

_CADDY_BIN = os.environ.get("BROKER_CADDY_BIN", "/usr/local/bin/caddy")
_TLS_MODE = os.environ.get("YASHIGANI_TLS_MODE", "acme").strip() or "acme"
_BASELINE_DIR = os.environ.get("BROKER_BASELINE_DIR", "/app/reference")

# BASELINE MODE — two sources, chosen by runtime (see "BASELINE IMMUNITY"
# above for why each is safe on its own runtime and NOT interchangeable):
#   "baked" (compose default) — pre-computed at image build time from the
#       repo's own Caddyfile copies (Dockerfile.caddy-broker "baseline"
#       stage). Required on compose because docker/caddy/agents/*.caddy AND
#       the Caddyfile.{csp,ollama-front,openclaw-egress,openclaw-webhooks}
#       snippet files are backoffice-writable via its RW docker/ tree mount
#       — a baseline re-derived from those live files at runtime could be
#       poisoned identically to the candidate, defeating the comparison.
#   "live" (K8s) — computed ONCE at container startup by reading the
#       ConfigMap-mounted Caddyfile (BROKER_LIVE_CADDYFILE) live, agents-
#       import stripped the same way. This is safe ON K8S SPECIFICALLY
#       because no workload ServiceAccount in this chart (helm/yashigani/
#       templates/*.yaml — audited 2026-07-21, zero RBAC rules grant
#       "configmaps" as a resource) has ANY API permission to mutate a
#       ConfigMap; the yashigani-caddy-config / yashigani-caddy-agents
#       ConfigMaps are Helm/kubectl-managed only. R2 (the compose-specific
#       "backoffice writes a rogue agents/*.caddy file" vector) has NO
#       equivalent on K8s for this reason — do NOT assume "live" mode is
#       safe on any runtime where the source file/dir could be
#       workload-writable.
_BASELINE_MODE = os.environ.get("BROKER_BASELINE_MODE", "baked").strip().lower()
_LIVE_CADDYFILE = os.environ.get("BROKER_LIVE_CADDYFILE", "/etc/caddy/Caddyfile")

_REAL_ADMIN_SOCKET = os.environ.get(
    "BROKER_REAL_ADMIN_SOCKET", "/run/caddy-admin/admin.sock",
)
_ADAPT_TIMEOUT_S = int(os.environ.get("BROKER_ADAPT_TIMEOUT_S", "10"))
_FORWARD_TIMEOUT_S = int(os.environ.get("BROKER_FORWARD_TIMEOUT_S", "15"))
_MAX_BODY_BYTES = int(os.environ.get("BROKER_MAX_BODY_BYTES", str(2 * 1024 * 1024)))

# Transport: compose runtimes bind a unix socket (BROKER_LISTEN_SOCKET);
# K8s co-locates this as a sidecar in the caddy pod and binds loopback TCP
# (BROKER_LISTEN_HOST/BROKER_LISTEN_PORT) — no emptyDir socket-sharing needed
# within a pod's shared network namespace, and no Service/Ingress ever fronts
# this port (pod-internal only, mirrors the extractor-svc internal-bridge
# posture on compose).
_LISTEN_MODE = os.environ.get("BROKER_LISTEN_MODE", "unix").strip().lower()
_LISTEN_SOCKET = os.environ.get("BROKER_LISTEN_SOCKET", "/run/caddy-broker/broker.sock")
_LISTEN_HOST = os.environ.get("BROKER_LISTEN_HOST", "127.0.0.1")
_LISTEN_PORT = int(os.environ.get("BROKER_LISTEN_PORT", "8199"))

_JOB_LOCK = threading.Lock()


class BrokerError(Exception):
    """Raised on any adapt/parse failure — always treated as a REJECT."""


# ---------------------------------------------------------------------------
# caddy adapt + invariant extraction
# ---------------------------------------------------------------------------

def _adapt_text(caddyfile_text: str) -> dict:
    """Run `caddy adapt` on caddyfile_text, resolving `import` directives
    against THIS container's live mounted filesystem (the same absolute
    paths — /etc/caddy/agents/*.caddy, /etc/caddy/Caddyfile.csp, etc. — the
    real Caddy container reads). Raises BrokerError on any failure.
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".caddyfile", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(caddyfile_text)
        proc = subprocess.run(
            [_CADDY_BIN, "adapt", "--config", tmp_path, "--adapter", "caddyfile"],
            capture_output=True, timeout=_ADAPT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        raise BrokerError("caddy adapt timed out after %ds: %s" % (_ADAPT_TIMEOUT_S, exc))
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if proc.returncode != 0:
        raise BrokerError(
            "caddy adapt failed (exit %d): %s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace")[:500])
        )
    try:
        return json.loads(proc.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BrokerError("caddy adapt produced invalid JSON: %s" % exc)


def _extract_invariants(cfg: dict) -> dict:
    """Extract the trust-critical subset of an adapted Caddy config.

    Deliberately does NOT compare the whole config — legitimate onboarding
    grows the route list under the existing `:443` site on every approve, so
    a whole-tree equality check would false-positive-reject every real
    onboarding. Only the fields a compromised backoffice must never move.
    """
    apps = cfg.get("apps") or {}
    http_app = apps.get("http") or {}
    servers = http_app.get("servers") or {}

    listen_addrs: set[str] = set()
    for srv in servers.values():
        for addr in srv.get("listen") or []:
            listen_addrs.add(addr)

    ca_refs: list[dict] = []
    inline_hits: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("provider") == "inline":
                inline_hits.append(dict(node))
            ca = node.get("ca")
            if isinstance(ca, dict):
                ca_refs.append(dict(ca))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(cfg)

    tls_app = apps.get("tls") or {}
    return {
        "admin": cfg.get("admin"),
        "has_pki_app": "pki" in apps,
        "tls_automation": tls_app.get("automation"),
        "tls_certificates": tls_app.get("certificates"),
        "listen_addrs": listen_addrs,
        "ca_refs": ca_refs,
        "inline_hits": inline_hits,
    }


_AGENTS_IMPORT_SENTINEL = "import /etc/caddy/agents/*.caddy"


def _strip_agents_import(text: str) -> str:
    """Remove the agent-import sentinel line so an adapt of the result
    reflects STATIC content only — used to compute a baseline that cannot be
    influenced by whatever currently lives in the mutable agents directory."""
    lines = [ln for ln in text.splitlines() if _AGENTS_IMPORT_SENTINEL not in ln]
    return "\n".join(lines) + "\n"


def _load_baseline() -> dict:
    """Load the trust baseline and extract its invariants. Two modes — see
    "BASELINE MODE" above; raises on any failure (fail-closed: if the
    baseline can't load, the broker must not approve ANY reload)."""
    if _BASELINE_MODE == "live":
        with open(_LIVE_CADDYFILE, "r", encoding="utf-8") as f:
            text = f.read()
        cfg = _adapt_text(_strip_agents_import(text))
        return _extract_invariants(cfg)

    path = os.path.join(_BASELINE_DIR, "adapted-%s.json" % _TLS_MODE)
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    return _extract_invariants(cfg)


def validate_candidate(candidate_text: str, baseline: dict) -> tuple[bool, str]:
    """Returns (ok, reason). ok=False → the caller must 422 and MUST NOT
    forward to the real admin socket."""
    try:
        cfg = _adapt_text(candidate_text)
    except BrokerError as exc:
        return False, str(exc)

    inv = _extract_invariants(cfg)

    if inv["inline_hits"]:
        return False, (
            "inline cert/CA provider found (forbidden — trust material must "
            "be file-based, pinned paths only): %r" % inv["inline_hits"][:3]
        )

    if inv["admin"] != baseline["admin"]:
        return False, "admin directive changed: got %r, expected %r" % (
            inv["admin"], baseline["admin"],
        )

    if inv["has_pki_app"]:
        return False, "submitted config defines a pki app (forbidden)"

    if inv["tls_automation"] != baseline["tls_automation"]:
        return False, "tls automation/issuers changed from the pinned baseline"

    if inv["tls_certificates"] != baseline["tls_certificates"]:
        return False, (
            "tls certificates (Caddy's own server leaf cert/key) changed "
            "from the pinned baseline"
        )

    unexpected_listens = inv["listen_addrs"] - baseline["listen_addrs"]
    if unexpected_listens:
        return False, "unexpected new listen address(es): %r" % sorted(unexpected_listens)

    baseline_ca_pem_files: set[str] = set()
    for ca in baseline["ca_refs"]:
        for f in (ca.get("pem_files") or []):
            baseline_ca_pem_files.add(f)

    for ca in inv["ca_refs"]:
        provider = ca.get("provider")
        if provider not in (None, "file"):
            return False, "non-file CA provider found: %r" % provider
        for f in (ca.get("pem_files") or []):
            if f not in baseline_ca_pem_files:
                return False, "unexpected CA trust-anchor file: %r" % f

    return True, ""


# ---------------------------------------------------------------------------
# forward-to-real-admin-socket (unix domain socket HTTP client, stdlib only)
# ---------------------------------------------------------------------------

class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: int) -> None:
        super().__init__("localhost", timeout=timeout)
        self._unix_path = path

    def connect(self) -> None:  # noqa: D102 — stdlib override
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._unix_path)
        self.sock = sock


def _forward_to_real_admin(body: bytes, content_type: str) -> tuple[int, bytes]:
    conn = _UnixHTTPConnection(_REAL_ADMIN_SOCKET, timeout=_FORWARD_TIMEOUT_S)
    try:
        conn.request(
            "POST", "/load", body=body,
            headers={
                "Content-Type": content_type or "text/caddyfile",
                "Host": "localhost",
                "Content-Length": str(len(body)),
            },
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

_BASELINE_CACHE: dict | None = None
_BASELINE_LOAD_ERROR: str | None = None


class BrokerHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_request(self, code="-", size="-"):  # noqa: D102 — stdlib override
        logger.info("HTTP %s %s -> %s", self.command, self.path, code)

    def log_error(self, fmt, *args):  # noqa: D102 — stdlib override
        logger.error("HTTP error: " + fmt, *args)

    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 — stdlib naming convention
        if self.path in ("/healthz", "/healthz/"):
            if _BASELINE_CACHE is None:
                self._send(
                    503,
                    ("baseline not loaded: %s\n" % _BASELINE_LOAD_ERROR).encode(),
                )
                return
            self._send(200, b"ok\n")
            return
        self._send(404, b"not found\n")

    def do_POST(self):  # noqa: N802 — stdlib naming convention
        if self.path not in ("/load", "/load/"):
            self._send(404, b"not found\n")
            return
        if _BASELINE_CACHE is None:
            # Fail-closed: never approve a reload without a trusted baseline.
            self._send(
                503,
                ("broker baseline unavailable: %s\n" % _BASELINE_LOAD_ERROR).encode(),
            )
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send(400, b"invalid Content-Length\n")
            return
        if length <= 0:
            self._send(400, b"empty body\n")
            return
        if length > _MAX_BODY_BYTES:
            self._send(
                413,
                ("body %d bytes exceeds cap %d\n" % (length, _MAX_BODY_BYTES)).encode(),
            )
            return

        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "text/caddyfile")
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            self._send(400, b"body is not valid UTF-8\n")
            return

        with _JOB_LOCK:
            ok, reason = validate_candidate(text, _BASELINE_CACHE)
            if not ok:
                logger.warning("REJECTED /load submission: %s", reason)
                self._send(
                    422,
                    (
                        "rejected by FINDING-V412-CADDYADMIN-001 broker: %s\n"
                        % reason
                    ).encode(),
                )
                return
            try:
                status, resp_body = _forward_to_real_admin(body, content_type)
            except Exception as exc:  # noqa: BLE001 — never crash the handler
                logger.error("forward to real admin socket failed: %s", exc)
                self._send(
                    502,
                    ("broker could not reach the real admin API: %s\n" % exc).encode(),
                )
                return

        logger.info("APPROVED /load submission, forwarded (real admin returned %d)", status)
        self._send(status, resp_body, content_type="application/json")


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def server_bind(self) -> None:  # noqa: D102 — stdlib override
        socketserver.UnixStreamServer.server_bind(self)
        self.server_name = "unix"
        self.server_port = 0


def _load_baseline_or_die() -> None:
    global _BASELINE_CACHE, _BASELINE_LOAD_ERROR
    try:
        _BASELINE_CACHE = _load_baseline()
        logger.info(
            "baseline loaded OK (baseline_mode=%s tls_mode=%s admin=%r "
            "listen_addrs=%d ca_refs=%d)",
            _BASELINE_MODE, _TLS_MODE, _BASELINE_CACHE["admin"],
            len(_BASELINE_CACHE["listen_addrs"]), len(_BASELINE_CACHE["ca_refs"]),
        )
    except Exception as exc:  # noqa: BLE001 — fail-closed at startup too
        _BASELINE_LOAD_ERROR = str(exc)
        logger.error(
            "FAILED to load baked baseline (mode=%s): %s — broker will 503 "
            "every /load request until fixed (fail-closed, no partial trust)",
            _TLS_MODE, exc,
        )


def main() -> None:
    _load_baseline_or_die()

    if _LISTEN_MODE == "unix":
        listen_dir = os.path.dirname(_LISTEN_SOCKET)
        os.makedirs(listen_dir, exist_ok=True)
        if os.path.exists(_LISTEN_SOCKET):
            os.unlink(_LISTEN_SOCKET)
        httpd = UnixHTTPServer(_LISTEN_SOCKET, BrokerHandler)
        # 0666: the socket lives on a named volume shared ONLY with the caddy
        # service (never backoffice — see docker-compose.yml). Mirrors the
        # existing caddy_admin_sock precedent; isolation is the mount
        # boundary, not the file mode (belt-and-braces here).
        os.chmod(_LISTEN_SOCKET, 0o666)
        logger.info(
            "listening on unix socket %s (real_admin=%s tls_mode=%s)",
            _LISTEN_SOCKET, _REAL_ADMIN_SOCKET, _TLS_MODE,
        )
    elif _LISTEN_MODE == "tcp":
        httpd = http.server.HTTPServer((_LISTEN_HOST, _LISTEN_PORT), BrokerHandler)
        logger.info(
            "listening on %s:%d (real_admin=%s tls_mode=%s) — K8s co-located "
            "sidecar mode, loopback only, no Service ever fronts this port",
            _LISTEN_HOST, _LISTEN_PORT, _REAL_ADMIN_SOCKET, _TLS_MODE,
        )
    else:
        logger.error("invalid BROKER_LISTEN_MODE=%r (must be 'unix' or 'tcp')", _LISTEN_MODE)
        sys.exit(1)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
        httpd.server_close()


if __name__ == "__main__":
    main()
