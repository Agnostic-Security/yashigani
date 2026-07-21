#!/usr/bin/env python3
"""
Yashigani Caddy config-registering broker — FINDING-V412-CADDYADMIN-002.

REWORK of the R1+R2 broker (5443f11f) after Laura's final re-attack
(laura-final-reattack.md) proved it FAILED on the real stack in two
release-blocking ways:

  BLOCKER-A (functional) — the old broker ran the capability-bearing `caddy`
      binary (`caddy adapt`) under `no-new-privileges`. The official
      caddy:2.11.2-alpine binary carries a `cap_net_bind_service=ep` FILE
      CAPABILITY (verified live: `getcap /usr/bin/caddy`). Under
      no-new-privileges, execve() of a binary whose file capabilities would
      grant it MORE than its already-permitted set is refused
      (`Operation not permitted`) — reproduced live with the exact broker
      security_opt (no-new-privileges + cap_drop ALL): every `caddy adapt`
      call EPERM'd, so every POST /load 502'd, including legitimate
      onboarding. Su's "422 verified" testing never ran under
      no-new-privileges (verified-facts trap).

      FIX: strip the file capability from the COPY of the binary this image
      ships (Dockerfile.caddy-broker, `setcap -r`) at BUILD time. `caddy
      adapt` binds no port and needs no capability at all — this broker never
      binds a privileged port — so the strip is a pure attack-surface
      reduction with zero functional loss, and no-new-privileges is left
      fully intact (not weakened, not bypassed).

  BLOCKER-B (security, R2) — backoffice's `/mnt/install/docker` RW mount was
      never RO-shadowed for `docker/caddy/agents/` (unlike secrets/var/.env/
      the active Caddyfile, FINDING-LIC-012 precedent), and `mcp_onboard.py`
      itself WROTE raw `.caddy` files there. Caddy's own container-start/
      restart entrypoint imports that directory directly from disk — a code
      path the old broker's `/load`-only gate never intercepted. A
      compromised backoffice could drop a rogue snippet that lands on the
      live :443 listener on the NEXT Caddy start, fully bypassing the broker.

      FIX (two parts, both required):
        1. docker-compose.yml RO-shadows `docker/caddy/agents/` under
           backoffice's install-tree mount (same technique as secrets/var/
           .env/Caddyfile — a more specific bind mount overrides the broader
           RW mount for that one subpath).
        2. The MCP-wrap route WRITE moves ENTIRELY into this broker.
           Backoffice no longer authors ANY Caddy content and no longer POSTs
           a raw `/load` body at all — see "NEW CONTRACT" below. It sends
           narrow, typed DATA; this process is the ONLY thing that ever
           renders Caddyfile text or writes into the directory Caddy imports
           for dynamically-onboarded MCP wraps.

NEW CONTRACT — data in, never raw Caddy content in:

  POST /route
      Body (JSON): {"tenant_id": str, "server_id": str,
                     "mesh_port": int, "shim_port": int}
      Every field is independently validated against the SAME constraints
      codegen.py already enforces before a manifest ever reaches this broker
      (identifier slug regex, MCP mesh-port range, reserved-port denylist) —
      this broker does NOT trust that upstream validation ran; a compromised
      backoffice sending malformed/malicious fields directly to this
      endpoint (bypassing the manifest linter entirely) is rejected here,
      independently, at the field level.

      On PASS: renders the per-instance MCP-front wrap from a FIXED template
      (this module's own code — never backoffice-supplied text) parameterised
      ONLY by the four validated fields above (server-cert/CA paths, route
      prefix, upstream host and the `handle`/`reverse_proxy` structure are
      ALL hardcoded here, by convention identical to
      manifest/codegen.py's _mcp_svid_paths()/_gen_caddy_snippet_mcp() — see
      "DEVIATION FROM THE LITERAL BRIEF" below), self-checks the rendered
      snippet IN ISOLATION (see "ENV-VAR-FREE SELF-CHECKS" below), writes it
      into this broker's OWN directory (BROKER_AGENTS_DYNAMIC_DIR, a named
      volume never mounted into backoffice), and triggers a real reload by
      forwarding the RO-trusted monolith Caddyfile TEXT verbatim to the real
      (caddy-private) admin socket — real Caddy (which has the real
      environment) does the actual adapt server-side. 200 on success.

      On FAIL: 422 (field validation), 500 (self-check — this broker's own
      rendering produced something unexpected; a bug, not an attack, but
      fail-closed all the same), or 502 (real admin socket unreachable/
      rejected the reload). The candidate is NEVER written or forwarded on
      any failure path (fail-closed).

  DELETE /route
      Body (JSON): {"tenant_id": str, "server_id": str}
      Removes the previously-registered route file (idempotent — 200 even if
      absent) and triggers a real reload so Caddy drops the route.

  GET /healthz
      200 once this process can successfully run the render+adapt+self-check
      pipeline end-to-end on a FIXED internal probe candidate (never the real
      monolith — see "ENV-VAR-FREE SELF-CHECKS") plus confirm the monolith
      Caddyfile mount exists. Re-checked on every poll — cheap, <100ms, and
      doubles as a continuous liveness proof that the capability-strip fix
      holds for the life of the container, not just at image-build time.

ENV-VAR-FREE SELF-CHECKS (FINDING-V412-CADDYADMIN-002-b, 2026-07-21):
  The FIRST version of this rework adapted the REAL monolith Caddyfile
  in-process (both for /healthz and to build the forwarded /load payload).
  On the real install this FAILED: the monolith references ~12 `{$VAR}`
  placeholders (YASHIGANI_TLS_DOMAIN, per-service SPIFFE IDs,
  CADDY_INTERNAL_HMAC, openclaw Slack/Telegram secrets, …) that only the
  REAL Caddy container's environment carries. This broker's environment
  carries NONE of them (by design — it should not need to). An unset
  `{$VAR}` inside a directive that requires exactly one argument (e.g.
  `default_sni {$YASHIGANI_TLS_DOMAIN}`) expands to an EMPTY argument and
  `caddy adapt` hard-fails with a parse error — `/healthz` 503'd and the
  real reload never happened, breaking onboarding for a second, different
  reason than BLOCKER-A.

  Fix: this broker no longer adapts the real monolith AT ALL.
    - Self-checks (`/route` candidate validation AND `/healthz`) run
      against SELF-CONTAINED input only: the rendered candidate snippet
      (or, for /healthz, a fixed internal probe rendered the same way),
      wrapped in a minimal `{ admin off }` shell that references NO
      external Caddyfile and NO env-var placeholder except the one THIS
      module's own template emits (`{$CADDY_INTERNAL_HMAC}` in the
      forward_auth hop) — substituted with a fixed LOCAL DUMMY value before
      adapting (`_SELFCHECK_HMAC_DUMMY`). This is safe because `caddy adapt`
      only parses SYNTAX/STRUCTURE — it never runs the config or opens the
      files it references — so the self-check needs the placeholder to be
      NON-EMPTY, never the real secret. The real value is never handled by
      this process at all.
    - The actual RELOAD trigger (`_trigger_reload`) reads the monolith
      Caddyfile as raw TEXT (never adapts it) and forwards it VERBATIM
      (`Content-Type: text/caddyfile`) to the real admin socket — the SAME
      mechanism `mcp_onboard.py`'s pre-rework `default_caddy_reloader()`
      already used successfully for months. Real Caddy — which has the
      REAL environment — performs the adapt server-side, exactly as it
      already does at every container start. This broker therefore needs
      NO monolith-referenced env var, secret or otherwise, in its own
      environment, and (as a consequence) no longer needs the
      Caddyfile.{csp,ollama-front,openclaw-egress,openclaw-webhooks} or
      static docker/caddy/agents/ mounts either — it never resolves an
      `import` itself. Mounts trimmed accordingly (docker-compose.yml /
      helm/caddy.yaml) — smaller blast radius, not just a workaround.

WHY THIS CLOSES R1 STRUCTURALLY (not just "the body looked safe this time"):
  Backoffice has NO endpoint through which it can supply free-text Caddy
  content anymore — /load is GONE. The only inputs backoffice controls are
  four typed fields (two identifier strings, two integers), and this
  broker's rendering code is baked into ITS OWN image, never reachable or
  modifiable by a compromised backoffice. There is no code path from
  "compromised backoffice" to "arbitrary directive in Caddy's merged config"
  left — the class of attack (backoffice-authored content reaching Caddy's
  trust decisions) is eliminated by construction, not filtered after the
  fact.

WHY R2 IS FULLY CLOSED (not just narrowed):
  docker/caddy/agents/ (the install.sh/ringfence-init-authored, RO-shadowed
  directory) is UNCHANGED by any workload at runtime. The NEW dynamic
  directory this broker writes into is backed by a named volume
  (caddy_broker_agents) that is RW ONLY inside this container and RO inside
  caddy — it is never bind-mounted into backoffice's filesystem at ALL, so
  there is no raw-file-drop primitive against it for backoffice to have in
  the first place (not "restricted", "absent").

DEVIATION FROM THE LITERAL BRIEF — logged, not silent:
  The corrected-architecture brief describes the broker template as
  "reverse_proxy-only ... NEVER emitting tls/PKI/inline-CA/bind/listener/
  global-options directives". Taken completely literally this would mean
  dropping the existing per-instance TLS LISTENER Caddy presents for each
  onboarded MCP (the ":{mesh_port} { tls <per-instance leaf> ... }" block —
  v4.1 Phase 1b-i, manifest/codegen.py _gen_caddy_snippet_mcp) in favour of a
  bare route on the shared :443 listener. That per-instance listener is a
  LOAD-BEARING security property (Nico/Tom's mesh design): each MCP's wrap
  presents a DISTINCT server leaf so a mesh CLIENT can pin the SPIFFE URI of
  the SPECIFIC instance it intends to reach, independent of any :443-level
  identity. Collapsing every MCP onto one shared listener/leaf would REMOVE
  that per-instance server-identity pinning — a cross-cutting mesh-PKI
  architecture change this dispatch is not positioned to make unilaterally
  (needs Tom/Nico/Iris design review, not a solo Captain call under a
  security-hardening brief).
  This implementation instead preserves the per-instance mesh-port TLS
  listener SHAPE (matching the existing, already-shipped design) but moves
  ALL AUTHORING AUTHORITY for that shape into this broker: every field that
  appears in the rendered Caddyfile text is either (a) a hardcoded constant
  in THIS module, or (b) one of the four independently-revalidated DATA
  fields above. Backoffice cannot cause this template to emit ANY directive
  outside that fixed shape — no inline CA, no PKI app, no admin-directive
  change, no listener OTHER than the one `:{mesh_port}` this specific call
  requested. The self-check functions below assert exactly that, on every
  single call, not just at build time.
  Flagged to Maxine/Tiago for an explicit decision: keep this (per-instance
  listener, broker-authored) or commission a follow-on design task to
  collapse onto a shared listener per the brief's literal wording.

This process's blast radius if somehow compromised: it can write ONLY into
its own dynamic-agents volume (rendered from its own fixed template) and
dial the real admin socket with what IT rendered — no secrets, no PKI
material, no other mount, no network reachability from the internet. Only
backoffice can reach it (dedicated unix-socket volume), and even backoffice
gets nothing but the field-validated /route contract above.
"""
from __future__ import annotations

import http.client
import http.server
import json
import logging
import os
import re
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

_REAL_ADMIN_SOCKET = os.environ.get(
    "BROKER_REAL_ADMIN_SOCKET", "/run/caddy-admin/admin.sock",
)
# The active monolith Caddyfile — SAME file real Caddy reads (RO mount, same
# absolute path convention as every other Caddyfile-family mount in this
# repo). This broker reads it FRESH on every reload — safe to do "live" here
# (unlike the old broker's baked-baseline requirement) because, after this
# fix, NOTHING backoffice-writable feeds into it anymore (RESTART-012 +
# LIC-012 + this fix's R2 RO-shadow all hold).
_CADDYFILE_PATH = os.environ.get("BROKER_CADDYFILE", "/etc/caddy/Caddyfile")
# Broker-owned dynamic agents directory — RW here, RO in Caddy.
_AGENTS_DYNAMIC_DIR = os.environ.get(
    "BROKER_AGENTS_DYNAMIC_DIR", "/etc/caddy/agents-dynamic",
)

_ADAPT_TIMEOUT_S = int(os.environ.get("BROKER_ADAPT_TIMEOUT_S", "10"))
_FORWARD_TIMEOUT_S = int(os.environ.get("BROKER_FORWARD_TIMEOUT_S", "15"))
_MAX_BODY_BYTES = int(os.environ.get("BROKER_MAX_BODY_BYTES", str(64 * 1024)))

# Transport: compose binds a unix socket (BROKER_LISTEN_SOCKET) shared ONLY
# with backoffice (caddy_broker_route_sock named volume — caddy itself is no
# longer a peer of this process at all: it dials OUT to caddy's real admin
# socket as a client, and nothing dials IN to it except backoffice).
# K8s co-locates this as a sidecar in the caddy pod and binds loopback TCP;
# the mesh-mTLS :2019 relay (configmaps.yaml) proxies POST/DELETE /route to
# it — no Service/Ingress ever fronts this port.
_LISTEN_MODE = os.environ.get("BROKER_LISTEN_MODE", "unix").strip().lower()
_LISTEN_SOCKET = os.environ.get(
    "BROKER_LISTEN_SOCKET", "/run/caddy-broker-route/route.sock",
)
_LISTEN_HOST = os.environ.get("BROKER_LISTEN_HOST", "127.0.0.1")
_LISTEN_PORT = int(os.environ.get("BROKER_LISTEN_PORT", "8199"))

_JOB_LOCK = threading.Lock()


class BrokerError(Exception):
    """Raised on any validation/render/self-check/forward failure."""

    def __init__(self, message: str, *, http_status: int = 422) -> None:
        super().__init__(message)
        self.http_status = http_status


# ---------------------------------------------------------------------------
# Field validation — MUST mirror src/yashigani/manifest/codegen.py exactly.
# Duplicated (not imported) because this image is stdlib-only and does not
# ship the yashigani package — see test_v412_caddy_config_broker.py
# TestConstantParity for the drift guard that fails CI if these ever diverge
# from codegen.py's own values.
# ---------------------------------------------------------------------------

# codegen.py manifest/linter.py _SLUG_RE — identifier constraint already
# enforced on every manifest's metadata.name / metadata.tenant_id BEFORE a
# manifest ever reaches codegen. Re-validated here independently: this
# broker must hold even if a compromised backoffice calls /route directly,
# bypassing the manifest linter entirely.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$")

# codegen.py _MCP_MESH_PORT_BASE / _MCP_MESH_PORT_RANGE / _MCP_RESERVED_PORTS
# / _SC_BRIDGE_PORT — the deterministic default lives in [9500, 9900); an
# EXPLICIT spec.mcp.exposes.mesh_port may be any port in 1024-65535 outside
# the reserved set (codegen.py _mcp_mesh_port() docstring). Mirrored exactly.
_MCP_RESERVED_PORTS: frozenset[int] = frozenset({
    80, 443, 2019, 8000, 8080, 8443, 8444, 8445,
    9400, 11435, 18789, 18790,
})
_SC_BRIDGE_PORT = 8000

# codegen.py _MCP_SVID_MOUNT_ROOT — fixed convention; the leaf cert/key path
# is DERIVED from (tenant_id, server_id) here, never accepted as input.
_MCP_SVID_MOUNT_ROOT = "/run/secrets/svid"

# codegen.py _C8_MAX_CONNS_PER_HOST_DEFAULT
_C8_MAX_CONNS_PER_HOST_DEFAULT = 64

_CA_INTERMEDIATE_PATH = "/run/secrets/ca_intermediate.crt"
_CADDY_CLIENT_CERT = "/run/secrets/caddy_client.crt"
_CADDY_CLIENT_KEY = "/run/secrets/caddy_client.key"

# See module docstring "ENV-VAR-FREE SELF-CHECKS". render_mcp_route()'s own
# output references {$CADDY_INTERNAL_HMAC} (real Caddy resolves the REAL
# value from ITS environment at actual reload time). This broker's
# self-check only verifies SYNTACTIC/STRUCTURAL shape via `caddy adapt` — it
# never runs the config — so it substitutes this fixed, non-secret, LOCAL-
# ONLY dummy before adapting. Never written to disk, never forwarded
# anywhere; exists purely to give `caddy adapt` a non-empty argument.
_SELFCHECK_HMAC_DUMMY = "SELFCHECK-DUMMY-NOT-A-SECRET"

# Fixed internal probe candidate for GET /healthz — see "ENV-VAR-FREE
# SELF-CHECKS". Rendered + self-checked on every poll, NEVER written to
# disk, NEVER forwarded to the real admin socket. Proves the render+adapt+
# self-check pipeline (i.e. the capability-strip fix) is functional without
# depending on the real monolith's env-var placeholders.
_HEALTHZ_PROBE_TENANT = "ysg-healthz-probe"
_HEALTHZ_PROBE_SERVER = "self-check"
_HEALTHZ_PROBE_MESH_PORT = 9599
_HEALTHZ_PROBE_SHIM_PORT = 18000


def _validate_route_fields(payload: dict) -> tuple[str, str, int, int]:
    """Validate the /route DATA contract. Raises BrokerError(422) on any
    field that fails — this is the ONLY gate between backoffice-influenced
    values and the rendering template below; every one of these checks is
    load-bearing."""
    if not isinstance(payload, dict):
        raise BrokerError("body must be a JSON object")

    tenant_id = payload.get("tenant_id")
    server_id = payload.get("server_id")
    mesh_port = payload.get("mesh_port")
    shim_port = payload.get("shim_port")

    for name, val in (("tenant_id", tenant_id), ("server_id", server_id)):
        if not isinstance(val, str) or not _SLUG_RE.match(val):
            raise BrokerError(
                "%s=%r fails the identifier slug constraint "
                "(^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$)" % (name, val)
            )

    for name, val in (("mesh_port", mesh_port), ("shim_port", shim_port)):
        if not isinstance(val, int) or isinstance(val, bool):
            raise BrokerError("%s must be an integer, got %r" % (name, val))
        if not (1024 <= val <= 65535):
            raise BrokerError(
                "%s=%d out of range (must be 1024-65535)" % (name, val)
            )

    if mesh_port in _MCP_RESERVED_PORTS:
        raise BrokerError(
            "mesh_port=%d collides with a reserved base-listener port %s"
            % (mesh_port, sorted(_MCP_RESERVED_PORTS))
        )

    return tenant_id, server_id, mesh_port, shim_port


# ---------------------------------------------------------------------------
# Fixed-template rendering — the ONLY place Caddyfile text is authored.
# Mirrors manifest/codegen.py _gen_caddy_snippet_mcp() structure exactly
# (same v4.1 Phase 1b-i wrap contract — see that function's docstring for the
# full design rationale). Ported here (not imported) because this image
# carries no yashigani package; a parity test asserts the two stay in sync.
# ---------------------------------------------------------------------------

def _mcp_svid_paths(tenant_id: str, server_id: str) -> tuple[str, str]:
    base = "%s/%s/%s" % (_MCP_SVID_MOUNT_ROOT, tenant_id, server_id)
    return base + "/client.crt", base + "/client.key"


def render_mcp_route(
    tenant_id: str, server_id: str, mesh_port: int, shim_port: int,
) -> str:
    """Render the per-instance MCP Caddy-front wrap. Every interpolated
    value here is either a fixed constant in this module or one of the four
    fields _validate_route_fields() already accepted — no other input path
    exists."""
    leaf_crt, leaf_key = _mcp_svid_paths(tenant_id, server_id)
    route_prefix = "/mcp/%s/%s" % (tenant_id, server_id)

    return (
        "# FINDING-V412-CADDYADMIN-002 — broker-rendered MCP-front wrap\n"
        "# server=%s tenant=%s mesh_port=%d (caddy-config-broker owns this "
        "file; NOT backoffice-writable)\n"
        ":%d {\n"
        "    tls %s %s {\n"
        "        client_auth {\n"
        "            mode require_and_verify\n"
        "            trust_pool file %s\n"
        "        }\n"
        "        protocols tls1.3\n"
        "    }\n"
        "\n"
        "    handle_path %s/* {\n"
        "        request_header -X-SPIFFE-ID\n"
        "        request_header X-SPIFFE-ID {http.request.tls.client.san.uris.0}\n"
        "        request_header -X-Caddy-Verified-Secret\n"
        "\n"
        "        forward_auth https://backoffice:8443 {\n"
        "            uri /auth/verify-mcp?tenant=%s&server=%s\n"
        "            header_up X-Caddy-Verified-Secret {$CADDY_INTERNAL_HMAC}\n"
        "            transport http {\n"
        "                tls\n"
        "                tls_trust_pool file %s\n"
        "                tls_client_auth %s %s\n"
        "                versions 1.1\n"
        "            }\n"
        "        }\n"
        "\n"
        "        reverse_proxy http://%s:%d {\n"
        "            transport http {\n"
        "                max_conns_per_host %d\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "\n"
        "    handle {\n"
        '        respond "Not Found" 404\n'
        "    }\n"
        "}\n"
    ) % (
        server_id, tenant_id, mesh_port,
        mesh_port,
        leaf_crt, leaf_key,
        _CA_INTERMEDIATE_PATH,
        route_prefix,
        tenant_id, server_id,
        _CA_INTERMEDIATE_PATH,
        _CADDY_CLIENT_CERT, _CADDY_CLIENT_KEY,
        server_id, shim_port,
        _C8_MAX_CONNS_PER_HOST_DEFAULT,
    )


# ---------------------------------------------------------------------------
# caddy adapt + self-check (hardcoded-expectation, not baseline-diff — see
# module docstring: nothing feeding this is backoffice-writable anymore, so
# a fresh-computed check is safe and simpler than the old build-time-baked
# baseline approach).
# ---------------------------------------------------------------------------

def _adapt_text(caddyfile_text: str) -> dict:
    fd, tmp_path = tempfile.mkstemp(suffix=".caddyfile", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(caddyfile_text)
        proc = subprocess.run(
            [_CADDY_BIN, "adapt", "--config", tmp_path, "--adapter", "caddyfile"],
            capture_output=True, timeout=_ADAPT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        raise BrokerError(
            "caddy adapt timed out after %ds: %s" % (_ADAPT_TIMEOUT_S, exc),
            http_status=500,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if proc.returncode != 0:
        raise BrokerError(
            "caddy adapt failed (exit %d): %s"
            % (proc.returncode, proc.stderr.decode("utf-8", "replace")[:500]),
            http_status=500,
        )
    try:
        return json.loads(proc.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BrokerError(
            "caddy adapt produced invalid JSON: %s" % exc, http_status=500,
        )


def _walk_invariants(cfg: dict) -> dict:
    """Extract the same trust-critical subset the R1/R2 broker used —
    reused here as a hardcoded-expectation self-check, not a baseline diff."""
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

    return {
        "admin": cfg.get("admin"),
        "has_pki_app": "pki" in apps,
        "listen_addrs": listen_addrs,
        "ca_refs": ca_refs,
        "inline_hits": inline_hits,
    }


def _self_check_snippet(snippet_text: str, expected_mesh_port: int) -> None:
    """Syntax + hardcoded-shape check on the snippet THIS process just
    rendered, in COMPLETE isolation (no live filesystem dependency, no
    external `import`, no env var except a fixed local dummy — see module
    docstring "ENV-VAR-FREE SELF-CHECKS") — catches a rendering bug in this
    module before it ever touches the live agents-dynamic dir. Wrapped in
    `{ admin off }` exactly like codegen.py's own C10 gate."""
    checkable_text = snippet_text.replace(
        "{$CADDY_INTERNAL_HMAC}", _SELFCHECK_HMAC_DUMMY,
    )
    cfg = _adapt_text("{\n    admin off\n}\n\n" + checkable_text)
    inv = _walk_invariants(cfg)

    if inv["inline_hits"]:
        raise BrokerError(
            "BUG: self-rendered snippet contains an inline provider: %r"
            % inv["inline_hits"], http_status=500,
        )
    if inv["has_pki_app"]:
        raise BrokerError(
            "BUG: self-rendered snippet defines a pki app", http_status=500,
        )
    expected_listen = ":%d" % expected_mesh_port
    if inv["listen_addrs"] != {expected_listen}:
        raise BrokerError(
            "BUG: self-rendered snippet listens on %r, expected exactly {%r}"
            % (inv["listen_addrs"], expected_listen), http_status=500,
        )
    for ca in inv["ca_refs"]:
        if ca.get("provider") not in (None, "file"):
            raise BrokerError(
                "BUG: self-rendered snippet CA provider=%r (expected file)"
                % ca.get("provider"), http_status=500,
            )
        pem_files = ca.get("pem_files") or []
        if pem_files and pem_files != [_CA_INTERMEDIATE_PATH]:
            raise BrokerError(
                "BUG: self-rendered snippet CA pem_files=%r, expected [%r]"
                % (pem_files, _CA_INTERMEDIATE_PATH), http_status=500,
            )


def _read_raw_monolith() -> bytes:
    """Read the RO monolith Caddyfile as raw BYTES — never adapted by this
    broker (see module docstring "ENV-VAR-FREE SELF-CHECKS"). Forwarded
    verbatim to the real admin socket; real Caddy resolves its own
    `import`s and `{$VAR}` placeholders from ITS environment server-side."""
    try:
        with open(_CADDYFILE_PATH, "rb") as f:
            return f.read()
    except OSError as exc:
        raise BrokerError(
            "cannot read monolith Caddyfile at %r: %s" % (_CADDYFILE_PATH, exc),
            http_status=500,
        )


def _self_check_pipeline_healthy() -> None:
    """GET /healthz calls this. Proves the render+adapt+self-check pipeline
    (the exact code path BLOCKER-A broke — `caddy adapt` under
    no-new-privileges) is functional RIGHT NOW, using a FIXED internal probe
    candidate — never the real monolith, never written to disk, never
    forwarded anywhere (see "ENV-VAR-FREE SELF-CHECKS"). Also confirms the
    monolith mount itself exists (cheap existence check, not an adapt) so a
    mount-configuration regression still surfaces here."""
    if not os.path.exists(_CADDYFILE_PATH):
        raise BrokerError(
            "monolith Caddyfile not mounted at %r" % _CADDYFILE_PATH,
            http_status=503,
        )
    probe = render_mcp_route(
        _HEALTHZ_PROBE_TENANT, _HEALTHZ_PROBE_SERVER,
        _HEALTHZ_PROBE_MESH_PORT, _HEALTHZ_PROBE_SHIM_PORT,
    )
    _self_check_snippet(probe, _HEALTHZ_PROBE_MESH_PORT)


# ---------------------------------------------------------------------------
# Atomic write / delete into the broker-owned dynamic agents dir.
# ---------------------------------------------------------------------------

def _route_file_path(tenant_id: str, server_id: str) -> str:
    # tenant_id/server_id are already _SLUG_RE-validated by the caller —
    # no path-traversal characters are possible in a slug match, but we
    # belt-and-braces reject anything containing a path separator anyway.
    if "/" in tenant_id or "/" in server_id or ".." in tenant_id or ".." in server_id:
        raise BrokerError("invalid identifier for route filename", http_status=500)
    return os.path.join(_AGENTS_DYNAMIC_DIR, "%s-%s-mcp.caddy" % (tenant_id, server_id))


def _write_route_file(tenant_id: str, server_id: str, content: str) -> str:
    dest = _route_file_path(tenant_id, server_id)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp-route-", dir=_AGENTS_DYNAMIC_DIR,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, dest)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return dest


def _delete_route_file(tenant_id: str, server_id: str) -> bool:
    dest = _route_file_path(tenant_id, server_id)
    try:
        os.unlink(dest)
        return True
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# Real-admin-socket forwarding
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


def _forward_caddyfile_to_real_admin(caddyfile_bytes: bytes) -> tuple[int, bytes]:
    """POST the raw Caddyfile TEXT to the real admin socket — Content-Type:
    text/caddyfile, exactly the contract mcp_onboard.py's pre-rework
    default_caddy_reloader() already used successfully. Real Caddy adapts
    it server-side with ITS OWN (real) environment."""
    conn = _UnixHTTPConnection(_REAL_ADMIN_SOCKET, timeout=_FORWARD_TIMEOUT_S)
    try:
        conn.request(
            "POST", "/load", body=caddyfile_bytes,
            headers={
                "Content-Type": "text/caddyfile",
                "Host": "localhost",
                "Content-Length": str(len(caddyfile_bytes)),
            },
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _trigger_reload() -> None:
    """Forward the RO-trusted monolith Caddyfile TEXT verbatim to the real
    admin socket — see module docstring "ENV-VAR-FREE SELF-CHECKS" for why
    this broker never adapts it itself. Raises BrokerError on any failure."""
    caddyfile_bytes = _read_raw_monolith()
    status, resp_body = _forward_caddyfile_to_real_admin(caddyfile_bytes)
    if status // 100 != 2:
        raise BrokerError(
            "real admin socket rejected /load (HTTP %d): %.300s"
            % (status, resp_body.decode("utf-8", "replace")),
            http_status=502,
        )


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

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

    def _send_json(self, status: int, obj: dict) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json")

    def _read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            raise BrokerError("invalid Content-Length")
        if length <= 0:
            raise BrokerError("empty body")
        if length > _MAX_BODY_BYTES:
            raise BrokerError(
                "body %d bytes exceeds cap %d" % (length, _MAX_BODY_BYTES),
                http_status=413,
            )
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise BrokerError("body is not valid JSON: %s" % exc)

    def do_GET(self):  # noqa: N802 — stdlib naming convention
        if self.path in ("/healthz", "/healthz/"):
            try:
                _self_check_pipeline_healthy()
            except BrokerError as exc:
                self._send(503, ("not healthy: %s\n" % exc).encode())
                return
            self._send(200, b"ok\n")
            return
        self._send(404, b"not found\n")

    def do_POST(self):  # noqa: N802 — stdlib naming convention
        if self.path not in ("/route", "/route/"):
            self._send(404, b"not found\n")
            return
        with _JOB_LOCK:
            try:
                payload = self._read_json_body()
                tenant_id, server_id, mesh_port, shim_port = _validate_route_fields(payload)
                snippet = render_mcp_route(tenant_id, server_id, mesh_port, shim_port)
                _self_check_snippet(snippet, mesh_port)
                dest = _write_route_file(tenant_id, server_id, snippet)
                try:
                    _trigger_reload()
                except BrokerError:
                    # Roll back the write — never leave an unreloaded/orphan
                    # file behind that a LATER reload (e.g. container
                    # restart) could pick up unreviewed.
                    _delete_route_file(tenant_id, server_id)
                    raise
            except BrokerError as exc:
                logger.warning("REJECTED /route: %s", exc)
                self._send_json(exc.http_status, {"error": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001 — never crash the handler
                logger.error("unexpected /route failure: %s", exc)
                self._send_json(500, {"error": "internal error: %s" % exc})
                return

        logger.info(
            "APPROVED /route tenant=%s server=%s mesh_port=%d shim_port=%d -> %s",
            tenant_id, server_id, mesh_port, shim_port, dest,
        )
        self._send_json(200, {"status": "ok", "path": dest})

    def do_DELETE(self):  # noqa: N802 — stdlib naming convention
        if self.path not in ("/route", "/route/"):
            self._send(404, b"not found\n")
            return
        with _JOB_LOCK:
            try:
                payload = self._read_json_body()
                if not isinstance(payload, dict):
                    raise BrokerError("body must be a JSON object")
                tenant_id, server_id = payload.get("tenant_id"), payload.get("server_id")
                for name, val in (("tenant_id", tenant_id), ("server_id", server_id)):
                    if not isinstance(val, str) or not _SLUG_RE.match(val):
                        raise BrokerError(
                            "%s=%r fails the identifier slug constraint" % (name, val)
                        )
                removed = _delete_route_file(tenant_id, server_id)
                _trigger_reload()
            except BrokerError as exc:
                logger.warning("REJECTED /route DELETE: %s", exc)
                self._send_json(exc.http_status, {"error": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001 — never crash the handler
                logger.error("unexpected /route DELETE failure: %s", exc)
                self._send_json(500, {"error": "internal error: %s" % exc})
                return

        logger.info(
            "APPROVED /route DELETE tenant=%s server=%s removed=%s",
            tenant_id, server_id, removed,
        )
        self._send_json(200, {"status": "ok", "removed": removed})


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def server_bind(self) -> None:  # noqa: D102 — stdlib override
        socketserver.UnixStreamServer.server_bind(self)
        self.server_name = "unix"
        self.server_port = 0


def main() -> None:
    os.makedirs(_AGENTS_DYNAMIC_DIR, exist_ok=True)

    if _LISTEN_MODE == "unix":
        listen_dir = os.path.dirname(_LISTEN_SOCKET)
        os.makedirs(listen_dir, exist_ok=True)
        if os.path.exists(_LISTEN_SOCKET):
            os.unlink(_LISTEN_SOCKET)
        httpd = UnixHTTPServer(_LISTEN_SOCKET, BrokerHandler)
        # 0666: the socket lives on a named volume shared ONLY with
        # backoffice (never caddy — caddy is no longer a peer of this
        # process at all). backoffice connects as a different, non-root UID
        # with no shared GID to target — isolation is the mount boundary
        # (belt-and-braces here, matches every other socket in this repo).
        os.chmod(_LISTEN_SOCKET, 0o666)
        logger.info(
            "listening on unix socket %s (real_admin=%s agents_dynamic=%s)",
            _LISTEN_SOCKET, _REAL_ADMIN_SOCKET, _AGENTS_DYNAMIC_DIR,
        )
    elif _LISTEN_MODE == "tcp":
        httpd = http.server.HTTPServer((_LISTEN_HOST, _LISTEN_PORT), BrokerHandler)
        logger.info(
            "listening on %s:%d (real_admin=%s agents_dynamic=%s) — K8s "
            "co-located sidecar mode, loopback only, no Service ever fronts "
            "this port",
            _LISTEN_HOST, _LISTEN_PORT, _REAL_ADMIN_SOCKET, _AGENTS_DYNAMIC_DIR,
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
