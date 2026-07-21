"""
Unit tests for docker/caddy/config_broker.py — FINDING-V412-CADDYADMIN-002.

REWORK of the R1+R2 broker's regression suite (5443f11f) after Laura's final
re-attack (laura-final-reattack.md) proved the OLD broker FAILED live in two
release-blocking ways (BLOCKER-A: `caddy adapt` EPERM'd under
no-new-privileges; BLOCKER-B: R2 filesystem-drop still open). The corrected
architecture replaces "validate an arbitrary /load body against a baked
baseline" with "render a fixed template from narrow, independently
revalidated DATA fields, self-check the result, write it into a
broker-owned volume, and trigger the reload" — see config_broker.py module
docstring for the full writeup. This file is the SOP5 regression net for
that NEW contract (in-process proof; the live two-container proof under the
REAL no-new-privileges security context was run manually during the fix and
is cited in the dispatch report).

The broker lives at a non-importable path (it is baked into its own image,
not the yashigani package), so we load it by file path via importlib — same
pattern as src/tests/unit/test_extractor_worker.py for
docker/extractor/worker.py.

Requires a local `caddy` binary (the SAME structural check config_broker.py
itself performs — `caddy adapt` is the source of truth, never a hand-rolled
Caddyfile parser). Skipped if absent, matching codegen.py's C10
`_validate_caddy_snippet` precedent (LAURA-005).
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import pathlib
import shutil
import socket
import tempfile
import threading
import time

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_BROKER_PATH = _REPO_ROOT / "docker" / "caddy" / "config_broker.py"

_CADDY_BIN = shutil.which("caddy")
pytestmark = pytest.mark.skipif(
    _CADDY_BIN is None,
    reason="no local `caddy` binary — this suite validates against the REAL "
           "adapter (never a hand-rolled parser), matching codegen.py C10",
)


def _load_broker():
    spec = importlib.util.spec_from_file_location("ysg_config_broker", _BROKER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def broker(monkeypatch):
    mod = _load_broker()
    monkeypatch.setattr(mod, "_CADDY_BIN", _CADDY_BIN)
    return mod


_VALID = dict(tenant_id="acme-corp", server_id="filesystem", mesh_port=9611, shim_port=8000)

# Minimal Caddyfile fixture the full-merge self-check reads — NOT the real
# production family (this suite tests the VALIDATION LOGIC in isolation).
_MONOLITH_FIXTURE = """\
{
    admin unix//run/caddy-admin/admin.sock|0666
}

:443 {
    tls internal
    respond "edge" 200
}

import /etc/caddy/agents-dynamic/*.caddy
"""

_MONOLITH_WITH_PKI_APP = """\
{
    admin unix//run/caddy-admin/admin.sock|0666
    pki {
        ca local {
            name "rogue"
        }
    }
}

:443 {
    tls internal
    respond "edge" 200
}
"""


# ---------------------------------------------------------------------------
# Constant parity — must mirror src/yashigani/manifest/codegen.py exactly
# (config_broker.py duplicates these because its image ships no yashigani
# package). Drift here silently reopens/narrows the mesh-port allowlist.
# ---------------------------------------------------------------------------

class TestConstantParity:
    def test_mesh_port_reserved_set_matches_codegen(self, broker):
        from yashigani.manifest.codegen import _MCP_RESERVED_PORTS as codegen_reserved
        from yashigani.manifest.codegen import _SC_BRIDGE_PORT as codegen_bridge_port

        assert broker._MCP_RESERVED_PORTS == frozenset(codegen_reserved)
        assert broker._SC_BRIDGE_PORT == codegen_bridge_port

    def test_svid_mount_root_matches_codegen(self, broker):
        from yashigani.manifest.codegen import _MCP_SVID_MOUNT_ROOT as codegen_root

        assert broker._MCP_SVID_MOUNT_ROOT == codegen_root

    def test_c8_max_conns_matches_codegen(self, broker):
        from yashigani.manifest.codegen import (
            _C8_MAX_CONNS_PER_HOST_DEFAULT as codegen_c8,
        )

        assert broker._C8_MAX_CONNS_PER_HOST_DEFAULT == codegen_c8

    def test_slug_regex_matches_linter(self, broker):
        from yashigani.manifest.linter import _SLUG_RE as linter_slug_re

        assert broker._SLUG_RE.pattern == linter_slug_re.pattern

    def test_svid_paths_match_codegen_convention(self, broker):
        from yashigani.manifest.codegen import _mcp_svid_paths as codegen_svid_paths

        assert broker._mcp_svid_paths("acme-corp", "filesystem") == \
            codegen_svid_paths("acme-corp", "filesystem")


# ---------------------------------------------------------------------------
# Field validation — the ONLY gate between backoffice-influenced input and
# the fixed rendering template.
# ---------------------------------------------------------------------------

class TestValidateRouteFields:
    def test_valid_fields_pass(self, broker):
        tenant_id, server_id, mesh_port, shim_port = broker._validate_route_fields(_VALID)
        assert (tenant_id, server_id, mesh_port, shim_port) == (
            "acme-corp", "filesystem", 9611, 8000,
        )

    @pytest.mark.parametrize("bad_id", [
        "", "Acme-Corp", "-leading-dash", "trailing-dash-", "has_underscore",
        "has space", "..", "../../etc", "a" * 65,
    ])
    def test_bad_tenant_id_rejected(self, broker, bad_id):
        payload = dict(_VALID, tenant_id=bad_id)
        with pytest.raises(broker.BrokerError) as exc:
            broker._validate_route_fields(payload)
        assert exc.value.http_status == 422

    @pytest.mark.parametrize("bad_id", [
        "", "Filesystem", "has_underscore", "; rm -rf /", "$(whoami)",
    ])
    def test_bad_server_id_rejected(self, broker, bad_id):
        payload = dict(_VALID, server_id=bad_id)
        with pytest.raises(broker.BrokerError):
            broker._validate_route_fields(payload)

    @pytest.mark.parametrize("bad_port", [2019, 8000, 8443, 8444, 8445, 9400, 11435])
    def test_reserved_mesh_port_rejected(self, broker, bad_port):
        """Reserved ports >= 1024 (below-1024 reserved ports like 80/443 are
        already caught by the plain range check — see
        test_out_of_range_or_wrong_type_mesh_port_rejected)."""
        payload = dict(_VALID, mesh_port=bad_port)
        with pytest.raises(broker.BrokerError) as exc:
            broker._validate_route_fields(payload)
        assert "reserved" in str(exc.value)

    @pytest.mark.parametrize("bad_port", [0, 1023, 70000, -1, "9611", True, 9611.5])
    def test_out_of_range_or_wrong_type_mesh_port_rejected(self, broker, bad_port):
        payload = dict(_VALID, mesh_port=bad_port)
        with pytest.raises(broker.BrokerError):
            broker._validate_route_fields(payload)

    def test_non_dict_body_rejected(self, broker):
        with pytest.raises(broker.BrokerError):
            broker._validate_route_fields(["not", "a", "dict"])

    def test_missing_field_rejected(self, broker):
        payload = dict(_VALID)
        del payload["shim_port"]
        with pytest.raises(broker.BrokerError):
            broker._validate_route_fields(payload)


# ---------------------------------------------------------------------------
# render_mcp_route — the ONLY place Caddyfile text is authored. Content
# contract mirrors manifest/codegen.py _gen_caddy_snippet_mcp() (ported, not
# imported).
# ---------------------------------------------------------------------------

class TestRenderMcpRoute:
    def test_snippet_contract(self, broker):
        snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)

        assert ":9611 {" in snip
        assert "handle_path /mcp/acme-corp/filesystem/*" in snip
        assert ("tls /run/secrets/svid/acme-corp/filesystem/client.crt "
                "/run/secrets/svid/acme-corp/filesystem/client.key") in snip
        assert "mode require_and_verify" in snip
        assert "trust_pool file /run/secrets/ca_intermediate.crt" in snip
        assert "protocols tls1.3" in snip
        assert "forward_auth https://backoffice:8443" in snip
        assert "uri /auth/verify-mcp?tenant=acme-corp&server=filesystem" in snip
        assert "tls_client_auth /run/secrets/caddy_client.crt /run/secrets/caddy_client.key" in snip
        assert "reverse_proxy http://filesystem:8000" in snip
        assert "max_conns_per_host 64" in snip
        assert "tls_insecure_skip_verify" not in snip
        assert 'respond "Not Found" 404' in snip
        # Never emits admin/pki directives — the whole point of moving
        # rendering authority here.
        assert "admin " not in snip
        assert "pki {" not in snip

    def test_adapts_cleanly_with_real_caddy(self, broker):
        snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)
        cfg = broker._adapt_text("{\n    admin off\n}\n\n" + snip)
        inv = broker._walk_invariants(cfg)
        assert inv["listen_addrs"] == {":9611"}
        assert not inv["inline_hits"]
        assert not inv["has_pki_app"]


# ---------------------------------------------------------------------------
# Self-checks — hardcoded-expectation gates (not baseline-diff — see module
# docstring: nothing feeding these is backoffice-writable anymore).
# ---------------------------------------------------------------------------

class TestSelfCheckSnippet:
    def test_correctly_rendered_snippet_passes(self, broker):
        snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)
        broker._self_check_snippet(snip, 9611)  # must not raise

    def test_wrong_listen_port_caught(self, broker):
        """Simulates a rendering bug: the snippet claims mesh_port=9611 but
        the caller expected 9612 — self-check must catch the mismatch."""
        snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)
        with pytest.raises(broker.BrokerError) as exc:
            broker._self_check_snippet(snip, 9612)
        assert exc.value.http_status == 500

    def test_injected_inline_provider_caught(self, broker):
        """Simulates a template-injection bug (should be structurally
        impossible given render_mcp_route's fixed template + validated
        inputs — this proves the self-check would catch it anyway, in
        depth)."""
        snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)
        tampered = snip.replace(
            "trust_pool file /run/secrets/ca_intermediate.crt",
            'trust_pool inline {\n                trust_der "AAAA"\n            }',
        )
        with pytest.raises(broker.BrokerError) as exc:
            broker._self_check_snippet(tampered, 9611)
        assert "inline" in str(exc.value)


class TestEnvVarFreeSelfChecks:
    """FINDING-V412-CADDYADMIN-002-b (Captain, 2026-07-21): the FIRST
    version of this rework adapted the REAL monolith Caddyfile in-process
    (both for /healthz and to build the /load payload). On the real
    install this failed: the monolith references ~12 `{$VAR}` placeholders
    (YASHIGANI_TLS_DOMAIN, per-service SPIFFE IDs, CADDY_INTERNAL_HMAC,
    openclaw secrets, …) this broker's own environment deliberately does
    not carry. An unset `{$VAR}` inside a single-argument directive (e.g.
    `default_sni {$YASHIGANI_TLS_DOMAIN}`) expands to an empty argument and
    `caddy adapt` hard-fails — /healthz 503'd and onboarding broke a SECOND
    way. This class proves the fix: the broker never adapts the real
    monolith at all — self-checks run against self-contained input only,
    and the reload trigger forwards the monolith as raw, un-adapted TEXT so
    real Caddy (which HAS the real environment) does the actual adapt."""

    def test_self_check_snippet_substitutes_the_hmac_placeholder(self, broker):
        """render_mcp_route()'s own output references
        {$CADDY_INTERNAL_HMAC} — the self-check must substitute a fixed
        LOCAL dummy before adapting, never require (or leak) the real
        secret, and never leave the placeholder unresolved (which would
        itself be a caddy adapt failure in SOME directive shapes)."""
        snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)
        assert "{$CADDY_INTERNAL_HMAC}" in snip  # sanity: the fixture we're testing actually has it
        broker._self_check_snippet(snip, 9611)  # must not raise

    def test_self_check_pipeline_healthy_never_touches_real_monolith(
        self, broker, tmp_path, monkeypatch,
    ):
        """GET /healthz's self-check must pass even when the monolith on
        disk is the REAL production Caddyfile shape — i.e. full of unset
        env-var placeholders that would fail to adapt if this broker tried
        to adapt it directly. Only monolith EXISTENCE is checked, never its
        content."""
        caddyfile = tmp_path / "Caddyfile"
        # A monolith shaped like the real one: an unset single-argument
        # env-var placeholder that would hard-fail `caddy adapt` if this
        # broker ever tried to adapt it (the exact live failure mode).
        caddyfile.write_text(
            "{\n    default_sni {$YASHIGANI_TLS_DOMAIN}\n}\n:443 {\n    respond \"ok\" 200\n}\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(broker, "_CADDYFILE_PATH", str(caddyfile))
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        broker._self_check_pipeline_healthy()  # must not raise

    def test_self_check_pipeline_unhealthy_when_monolith_mount_absent(
        self, broker, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(broker, "_CADDYFILE_PATH", str(tmp_path / "missing"))
        with pytest.raises(broker.BrokerError) as exc:
            broker._self_check_pipeline_healthy()
        assert exc.value.http_status == 503

    def test_read_raw_monolith_returns_bytes_unadapted(self, broker, tmp_path, monkeypatch):
        """The reload trigger must read the monolith VERBATIM — no adapt,
        no env-var resolution, no content inspection (that's real Caddy's
        job now, server-side, with its own real environment)."""
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(_MONOLITH_WITH_PKI_APP, encoding="utf-8")
        monkeypatch.setattr(broker, "_CADDYFILE_PATH", str(caddyfile))

        raw = broker._read_raw_monolith()
        assert raw == _MONOLITH_WITH_PKI_APP.encode("utf-8")

    def test_read_raw_monolith_unreadable_fails_closed(self, broker, tmp_path, monkeypatch):
        monkeypatch.setattr(broker, "_CADDYFILE_PATH", str(tmp_path / "missing"))
        with pytest.raises(broker.BrokerError) as exc:
            broker._read_raw_monolith()
        assert exc.value.http_status == 500


# ---------------------------------------------------------------------------
# HTTP handler — live, in-process proof (real UnixHTTPServer + a stub real-
# admin socket) that the fail-closed ordering holds end-to-end, not just in
# the pure functions.
# ---------------------------------------------------------------------------

class _StubAdminHandler:
    def __init__(self):
        self.calls = 0


def _run_stub_admin_socket(path: str, state: _StubAdminHandler, stop_event: threading.Event):
    import http.server
    import socketserver

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            state.calls += 1
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # noqa: D102 — silence stdlib default logging
            pass

    class UnixServer(socketserver.UnixStreamServer):
        allow_reuse_address = True

    srv = UnixServer(path, Handler)
    srv.timeout = 0.2
    while not stop_event.is_set():
        srv.handle_request()
    srv.server_close()


def _request_unix(sock_path: str, method: str, path: str, body: bytes) -> tuple[int, bytes]:
    class _UnixConn(http.client.HTTPConnection):
        def connect(self):  # noqa: D102
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(sock_path)
            self.sock = s

    last_exc: Exception | None = None
    for attempt in range(20):
        conn = _UnixConn("localhost", timeout=5)
        try:
            conn.request(method, path, body=body, headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            })
            resp = conn.getresponse()
            return resp.status, resp.read()
        except OSError as exc:
            last_exc = exc
            time.sleep(0.05 * (attempt + 1))
        finally:
            conn.close()
    raise AssertionError("could not connect to %s: %s" % (sock_path, last_exc))


class TestBrokerHttpServerLive:
    @pytest.fixture()
    def live_env(self, broker, tmp_path, monkeypatch):
        sock_dir = pathlib.Path(tempfile.mkdtemp(prefix="ysgb-"))
        real_admin_sock = str(sock_dir / "admin.sock")
        broker_sock = str(sock_dir / "route.sock")

        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(_MONOLITH_FIXTURE, encoding="utf-8")
        agents_dynamic = tmp_path / "agents-dynamic"
        agents_dynamic.mkdir()

        monkeypatch.setattr(broker, "_CADDYFILE_PATH", str(caddyfile))
        monkeypatch.setattr(broker, "_AGENTS_DYNAMIC_DIR", str(agents_dynamic))
        monkeypatch.setattr(broker, "_REAL_ADMIN_SOCKET", real_admin_sock)

        stop_event = threading.Event()
        stub_state = _StubAdminHandler()
        admin_thread = threading.Thread(
            target=_run_stub_admin_socket,
            args=(real_admin_sock, stub_state, stop_event),
            daemon=True,
        )
        admin_thread.start()
        time.sleep(0.1)

        httpd = broker.UnixHTTPServer(broker_sock, broker.BrokerHandler)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.1)

        try:
            yield broker_sock, stub_state, agents_dynamic
        finally:
            httpd.shutdown()
            stop_event.set()
            admin_thread.join(timeout=2)
            server_thread.join(timeout=2)

    def test_legit_route_registration_writes_file_and_reloads(self, live_env):
        broker_sock, stub_state, agents_dynamic = live_env
        status, body = _request_unix(
            broker_sock, "POST", "/route", json.dumps(_VALID).encode(),
        )
        assert status == 200, body
        assert stub_state.calls == 1, "approved registration must reach the real admin socket"
        written = list(agents_dynamic.glob("*.caddy"))
        assert len(written) == 1
        assert "acme-corp-filesystem-mcp.caddy" in written[0].name
        assert "handle_path /mcp/acme-corp/filesystem/*" in written[0].read_text()

    def test_malformed_fields_rejected_never_reaches_admin(self, live_env):
        broker_sock, stub_state, agents_dynamic = live_env
        payload = dict(_VALID, mesh_port=443)  # reserved port
        status, body = _request_unix(
            broker_sock, "POST", "/route", json.dumps(payload).encode(),
        )
        assert status == 422, body
        assert stub_state.calls == 0, (
            "a REJECTED submission must NEVER reach the real admin socket"
        )
        assert not list(agents_dynamic.glob("*.caddy"))

    def test_delete_route_removes_file_and_reloads(self, live_env):
        broker_sock, stub_state, agents_dynamic = live_env
        status, _ = _request_unix(broker_sock, "POST", "/route", json.dumps(_VALID).encode())
        assert status == 200
        assert len(list(agents_dynamic.glob("*.caddy"))) == 1

        del_payload = json.dumps({"tenant_id": "acme-corp", "server_id": "filesystem"}).encode()
        status2, body2 = _request_unix(broker_sock, "DELETE", "/route", del_payload)
        assert status2 == 200, body2
        assert not list(agents_dynamic.glob("*.caddy"))
        assert stub_state.calls == 2, "DELETE must also trigger a real reload"

    def test_delete_absent_route_is_idempotent(self, live_env):
        broker_sock, stub_state, agents_dynamic = live_env
        del_payload = json.dumps({"tenant_id": "acme-corp", "server_id": "never-onboarded"}).encode()
        status, body = _request_unix(broker_sock, "DELETE", "/route", del_payload)
        assert status == 200, body
        assert json.loads(body)["removed"] is False

    def test_healthz_ok_when_caddyfile_valid(self, live_env):
        broker_sock, _stub_state, _agents_dynamic = live_env
        status, body = _request_unix(broker_sock, "GET", "/healthz", b"")
        assert status == 200, body

    def test_healthz_ok_even_with_real_style_unset_env_placeholders(
        self, broker, tmp_path, monkeypatch,
    ):
        """FINDING-V412-CADDYADMIN-002-b live reproduction: a monolith
        shaped like the real production Caddyfile (an unset single-argument
        `{$VAR}` placeholder — the EXACT live failure Maxine diagnosed,
        `default_sni {$YASHIGANI_TLS_DOMAIN}` -> empty arg -> parse error)
        must NOT make /healthz unhealthy, because this broker never adapts
        the monolith at all anymore."""
        sock_dir = pathlib.Path(tempfile.mkdtemp(prefix="ysgb-"))
        broker_sock = str(sock_dir / "route.sock")
        caddyfile = tmp_path / "Caddyfile"
        caddyfile.write_text(
            "{\n    default_sni {$YASHIGANI_TLS_DOMAIN}\n    admin unix//run/caddy-admin/admin.sock|0666\n}\n"
            ":443 {\n    respond \"ok\" 200\n}\n"
            "import /etc/caddy/agents-dynamic/*.caddy\n",
            encoding="utf-8",
        )
        agents_dynamic = tmp_path / "agents-dynamic"
        agents_dynamic.mkdir()
        monkeypatch.setattr(broker, "_CADDYFILE_PATH", str(caddyfile))
        monkeypatch.setattr(broker, "_AGENTS_DYNAMIC_DIR", str(agents_dynamic))
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        httpd = broker.UnixHTTPServer(broker_sock, broker.BrokerHandler)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.1)
        try:
            status, body = _request_unix(broker_sock, "GET", "/healthz", b"")
            assert status == 200, body
        finally:
            httpd.shutdown()
            server_thread.join(timeout=2)

    def test_wrong_path_404(self, live_env):
        broker_sock, _stub_state, _agents_dynamic = live_env
        status, _ = _request_unix(broker_sock, "POST", "/load", b"{}")
        assert status == 404
        status2, _ = _request_unix(broker_sock, "GET", "/config/", b"")
        assert status2 == 404
