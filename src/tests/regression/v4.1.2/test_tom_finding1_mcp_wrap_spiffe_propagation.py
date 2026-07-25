# Last updated: 2026-07-21T00:00:00+00:00
"""
Regression test — FINDING-V412-ONBOARDING-ROBUSTNESS #1: per-instance
``:9611`` MCP mTLS listener returning ``401 no_spiffe_id`` from
``/auth/verify-mcp`` for EVERY caller (agent's own leaf AND the gateway mesh
identity), even though the TLS handshake and the ``forward_auth`` hop were
both live (Ava, ``testing_runs/yashigani/wt-fix-svid/evidence/
ava-onboarding-e2e-final.md``).

ROOT CAUSE (proven live against a real ``caddy`` binary, not guessed):
``forward_auth`` compiles into an INDEPENDENT subrequest to the auth
backend — it does NOT inherit headers set by an earlier ``request_header``
directive in the same ``handle_path`` block. Only ``header_up`` entries
declared INSIDE the ``forward_auth`` block itself reach the auth backend.
``docker/caddy/config_broker.py``'s ``render_mcp_route()`` (the live,
authoritative renderer for the per-instance MCP wrap — see
FINDING-V412-CADDYADMIN-002, which moved rendering authority out of
``manifest/codegen.py``'s now-dead-code ``_gen_caddy_snippet_mcp()``) set
``request_header X-SPIFFE-ID {http.request.tls.client.san.uris.0}`` but had
NO matching ``header_up X-SPIFFE-ID`` inside its ``forward_auth`` block —
unlike the sibling (working) ``_gen_agent_ingress_caddyfile`` pattern, which
already carried this ``header_up`` line. Backoffice's ``/auth/verify-mcp``
therefore never saw ``x-spiffe-id`` on ANY caller and 401'd
``no_spiffe_id`` unconditionally.

This test proves the bug AND the fix end-to-end against a real ``caddy``
binary + a real mTLS handshake + a real (mocked) auth backend — no docker/
podman stack required, matching the brief's "code + unit-test verification
only" scope:

  1. Renders the REAL production snippet via
     ``docker/caddy/config_broker.py render_mcp_route()``.
  2. Runs it under a real ``caddy run`` process on a loopback port, serving
     a self-signed per-instance leaf with a ``spiffe://`` URI SAN, requiring
     client certs signed by a throwaway CA.
  3. Points ``forward_auth`` at a real local HTTP server standing in for
     backoffice ``/auth/verify-mcp`` that echoes back every header it
     received.
  4. A client presents a valid mTLS leaf (its own ``spiffe://`` URI SAN) and
     the test asserts the mock auth backend RECEIVED ``x-spiffe-id`` with
     that exact value — this is exactly what the mock verify-mcp needs to
     stop 401'ing ``no_spiffe_id``.

Prior to the fix (``header_up X-SPIFFE-ID`` absent from the
``forward_auth`` block), this test fails: the mock auth backend receives
``Host``/``User-Agent``/``X-Forwarded-*`` but never ``x-spiffe-id`` —
reproduced manually against caddy 2.11.4 during root-cause analysis.
"""
from __future__ import annotations

import http.server
import importlib.util
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
_BROKER_PATH = _REPO_ROOT / "docker" / "caddy" / "config_broker.py"
_CADDY_BIN = shutil.which("caddy")
_CURL_BIN = shutil.which("curl")

pytestmark = pytest.mark.skipif(
    _CADDY_BIN is None or _CURL_BIN is None,
    reason="no local `caddy`/`curl` binary — this suite proves the fix "
           "against the REAL adapter/runtime, never a hand-rolled parser "
           "(matches test_v412_caddy_config_broker.py precedent)",
)


def _load_broker():
    spec = importlib.util.spec_from_file_location("ysg_config_broker_f1", _BROKER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _HeaderEchoHandler(http.server.BaseHTTPRequestHandler):
    """Stand-in for backoffice /auth/verify-mcp: records every header it
    received and always answers 200 (this test asserts on WHAT the auth
    backend saw, not on verify-mcp's own SPIFFE-allowlist logic — that is
    covered separately by src/tests/unit/test_v41_verify_mcp.py)."""

    received: list[dict] = []

    def do_GET(self):  # noqa: N802 - stdlib handler method name
        _HeaderEchoHandler.received.append(dict(self.headers.items()))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_a):  # silence stdlib access log
        pass


@pytest.fixture()
def broker(monkeypatch):
    mod = _load_broker()
    monkeypatch.setattr(mod, "_CADDY_BIN", _CADDY_BIN)
    return mod


@pytest.fixture()
def _pki(tmp_path):
    """A throwaway CA + per-instance server leaf (spiffe URI SAN + DNS
    localhost, matching the real svid-sidecar mint convention) + a mesh
    client leaf (spiffe URI SAN) — everything render_mcp_route()'s
    ``tls``/``client_auth``/``forward_auth transport`` stanzas reference."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    def _write_key(key, path):
        path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    def _write_cert(cert, path):
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def _leaf(cn: str, sans: list, eku_client: bool):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        )
        if eku_client:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        return key, cert

    server_key, server_cert = _leaf(
        "localhost",
        [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))],
        eku_client=False,
    )
    client_spiffe_id = "spiffe://test-td/agents/acme-corp/filesystem/nhi_deadbeef"
    client_key, client_cert = _leaf(
        "agent-leaf",
        [x509.UniformResourceIdentifier(client_spiffe_id), x509.DNSName("localhost")],
        eku_client=True,
    )

    d = tmp_path
    _write_cert(ca_cert, d / "ca.crt")
    _write_key(server_key, d / "server.key")
    _write_cert(server_cert, d / "server.crt")
    _write_key(client_key, d / "client.key")
    _write_cert(client_cert, d / "client.crt")

    return {
        "dir": d,
        "ca_crt": d / "ca.crt",
        "server_crt": d / "server.crt",
        "server_key": d / "server.key",
        "client_crt": d / "client.crt",
        "client_key": d / "client.key",
        "client_spiffe_id": client_spiffe_id,
    }


def test_forward_auth_block_carries_own_spiffe_header_up(broker):
    """Static contract: the header_up MUST live inside the forward_auth
    block, not just anywhere in the rendered file (a bare
    `"X-SPIFFE-ID" in snip` assertion would pass even if it only appeared
    in the earlier `request_header` line — the exact bug this finding is
    about)."""
    snip = broker.render_mcp_route("acme-corp", "filesystem", 9611, 8000)
    fwd_auth_block = snip.split("forward_auth https://backoffice:8443", 1)[1]
    fwd_auth_block = fwd_auth_block.split("reverse_proxy", 1)[0]
    assert "header_up X-SPIFFE-ID {http.request.tls.client.san.uris.0}" in fwd_auth_block


def test_mcp_wrap_forwards_spiffe_id_to_verify_mcp_backend(broker, _pki):
    """The end-to-end proof: run the REAL rendered snippet under a REAL
    caddy process, present a REAL mTLS client leaf, and assert the (mocked)
    /auth/verify-mcp backend actually received x-spiffe-id with the
    caller's SPIFFE URI. This is the exact signal verify_mcp_ingress()
    (backoffice/routes/auth.py) needs — its absence is precisely
    `401 no_spiffe_id`."""
    _HeaderEchoHandler.received = []
    auth_port = _free_port()
    auth_httpd = http.server.HTTPServer(("127.0.0.1", auth_port), _HeaderEchoHandler)
    auth_thread = threading.Thread(target=auth_httpd.serve_forever, daemon=True)
    auth_thread.start()

    mesh_port = _free_port()

    # Render the REAL production snippet, then substitute the fixed
    # production paths for our throwaway PKI + point forward_auth at the
    # local mock instead of https://backoffice:8443 (no live backoffice
    # required — this test isolates the Caddy-layer header-propagation bug,
    # which is where the fix lives).
    snip = broker.render_mcp_route("acme-corp", "filesystem", mesh_port, 8000)
    snip = snip.replace(
        "tls /run/secrets/svid/acme-corp/filesystem/client.crt "
        "/run/secrets/svid/acme-corp/filesystem/client.key",
        f"tls {_pki['server_crt']} {_pki['server_key']}",
    )
    snip = snip.replace(
        "trust_pool file /run/secrets/ca_intermediate.crt",
        f"trust_pool file {_pki['ca_crt']}",
    )
    snip = snip.replace(
        "forward_auth https://backoffice:8443 {",
        f"forward_auth http://127.0.0.1:{auth_port} {{",
    )
    # Drop the mTLS forward_auth transport block entirely — the mock is
    # plain HTTP; the real transport stanza is orthogonal to the bug/fix
    # under test (header propagation), so strip it rather than fake more PKI.
    lines = snip.splitlines()
    out = []
    skipping = False
    for ln in lines:
        if "transport http {" in ln:
            skipping = True
            continue
        if skipping and ln.strip() == "}":
            skipping = False
            continue
        if skipping:
            continue
        out.append(ln)
    snip = "\n".join(out)
    # reverse_proxy upstream (filesystem:8000) is unreachable in this test —
    # irrelevant: forward_auth's 200 response from the mock lets Caddy
    # continue to reverse_proxy, which will fail to dial and 502 further
    # down the chain, AFTER the assertion-relevant header capture already
    # happened on the auth hop. We don't assert on that 502.

    caddyfile = "{\n    admin off\n    auto_https off\n}\n\n" + snip

    with tempfile.TemporaryDirectory() as cfg_dir:
        cfg_path = pathlib.Path(cfg_dir) / "Caddyfile"
        cfg_path.write_text(caddyfile)
        proc = subprocess.Popen(
            [_CADDY_BIN, "run", "--config", str(cfg_path), "--adapter", "caddyfile"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            # Wait for the listener to come up.
            deadline = time.time() + 10
            up = False
            while time.time() < deadline:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    if s.connect_ex(("127.0.0.1", mesh_port)) == 0:
                        up = True
                        break
                time.sleep(0.2)
            assert up, "caddy did not bind the mesh listener in time"

            # curl, not python http.client/ssl: this box's system python3 is
            # linked against LibreSSL 2.8.3 (no TLS 1.3 support), which fails
            # the handshake against Caddy's default-modern TLS config for
            # reasons unrelated to the bug/fix under test. curl (system
            # libcurl/LibreSSL via SecureTransport or a newer OpenSSL) is the
            # same client Ava used to reproduce this live (per the finding's
            # evidence doc) and is available on every dev/CI box.
            curl_out = subprocess.run(
                [
                    "curl", "-sk", "--http1.1",
                    "--cert", str(_pki["client_crt"]),
                    "--key", str(_pki["client_key"]),
                    "--cacert", str(_pki["ca_crt"]),
                    # "localhost", not "127.0.0.1": Caddy enables strict
                    # SNI-Host enforcement whenever client_auth is
                    # configured, and the server leaf's SAN is DNS:localhost
                    # (matching the real per-instance-leaf convention) —
                    # an IP-literal target either omits SNI or sends one
                    # that doesn't match, yielding 421 Misdirected Request
                    # (verified empirically) before forward_auth ever runs.
                    f"https://localhost:{mesh_port}/mcp/acme-corp/filesystem/tools/call",
                    "-o", "/dev/null", "-w", "%{http_code}",
                ],
                capture_output=True, text=True, timeout=10,
            )
            assert curl_out.returncode == 0, (
                f"curl mTLS handshake failed: {curl_out.stderr}"
            )
            # We only assert the forward_auth hop's view of the request —
            # not the final status (which depends on the unreachable
            # upstream reverse_proxy, out of scope for this test).
            assert _HeaderEchoHandler.received, (
                "mock /auth/verify-mcp backend never received a request — "
                "forward_auth hop did not fire"
            )
            seen = _HeaderEchoHandler.received[-1]
            seen_lower = {k.lower(): v for k, v in seen.items()}
            assert "x-spiffe-id" in seen_lower, (
                "THE BUG: forward_auth's auth-subrequest never carried "
                "x-spiffe-id — reproduces FINDING-V412-ONBOARDING-"
                "ROBUSTNESS #1 (401 no_spiffe_id for every caller). "
                f"Headers actually received: {seen}"
            )
            assert seen_lower["x-spiffe-id"] == _pki["client_spiffe_id"]
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            auth_httpd.shutdown()
            auth_thread.join(timeout=5)
