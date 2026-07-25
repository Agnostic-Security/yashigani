"""
Unit tests — pki.ssl_context.client_ssl_context_verify_spiffe (FINDING C,
v4.1.2 final onboarding e2e).

Ground-truth: ring-fenced MCP agent per-instance Caddy fronts
(manifest/codegen.py::_gen_caddy_snippet_mcp) present a leaf whose ONLY SAN
is a spiffe:// URI — no DNS SAN. httpx/OpenSSL's default check_hostname
cannot match that, so the mesh client must verify by SPIFFE URI SAN instead.

These tests exercise the REAL TLS handshake path (asyncio start_server +
httpx.AsyncClient, and a raw-socket sync server + httpx.Client) against
certs built with the `cryptography` library — no mocking of the ssl module.

Required coverage (finding text):
  1. Correct SPIFFE URI SAN (no DNS SAN)      -> ACCEPTED
  2. Wrong / absent SPIFFE URI SAN            -> REJECTED
  3. Cert not chaining to the internal CA     -> REJECTED
  4. Chain verification is never disabled (CERT_REQUIRED throughout)
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
import threading
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from yashigani.pki.identity import ServiceIdentity
from yashigani.pki.ssl_context import (
    _check_spiffe_identity,
    _extract_spiffe_uris,
    client_ssl_context_verify_spiffe,
)

GOOD_SPIFFE = "spiffe://td.internal/agents/acme/demo-mcp/nhi_abc123"
WRONG_SPIFFE = "spiffe://td.internal/agents/acme/demo-mcp/nhi_WRONGWRONG"


# ─────────────────────────────────────────────────────────────────────────────
# Cert-building helpers (cryptography — same convention as test_pki_driver.py
# / test_pki_leaf_localhost_san.py; no openssl subprocess dependency)
# ─────────────────────────────────────────────────────────────────────────────


def _make_ca(cn: str) -> tuple[bytes, ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Self-signed test CA. Returns (root_pem, ca_key, ca_cert)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), key, cert


def _make_leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    *,
    cn: str,
    spiffe_uri: str | None,
) -> tuple[bytes, bytes]:
    """Leaf cert signed by ca_key/ca_cert. spiffe_uri=None -> no SAN at all
    (mirrors an unrelated/legacy cert with no URI SAN whatsoever)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if spiffe_uri is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@pytest.fixture
def pki_world(tmp_path: Path):
    """Build a self-contained CA + client (gateway) leaf + server (agent) leaf
    variants. Returns a namespace of file paths + a ServiceIdentity for the
    client side (fed to client_ssl_context_verify_spiffe(identity=...) so the
    test never touches YASHIGANI_SERVICE_NAME / real /run/secrets)."""

    class World:
        pass

    w = World()

    ca_pem, ca_key, ca_cert = _make_ca("test-internal-ca")
    other_ca_pem, other_ca_key, other_ca_cert = _make_ca("untrusted-other-ca")

    ca_root = tmp_path / "ca_root.crt"
    ca_root.write_bytes(ca_pem)
    w.ca_root = ca_root

    # Client (gateway) leaf — presented for mTLS to the agent front.
    client_cert_pem, client_key_pem = _make_leaf(
        ca_key, ca_cert, cn="gateway", spiffe_uri="spiffe://td.internal/gateway"
    )
    client_cert = tmp_path / "gateway_client.crt"
    client_cert.write_bytes(client_cert_pem)
    client_key = tmp_path / "gateway_client.key"
    client_key.write_bytes(client_key_pem)
    w.identity = ServiceIdentity(
        name="gateway",
        dns_sans=(),
        purpose="test",
        mtls_capable=True,
        bootstrap_token_sha256="",
        revoked=False,
        cert_path=client_cert,
        key_path=client_key,
        ca_root_path=ca_root,
    )

    # Server (agent) leaf — correct SPIFFE URI SAN, no DNS SAN, trusted chain.
    good_pem, good_key = _make_leaf(ca_key, ca_cert, cn="agent-leaf", spiffe_uri=GOOD_SPIFFE)
    w.good_server_cert = tmp_path / "agent_good.crt"
    w.good_server_cert.write_bytes(good_pem)
    w.good_server_key = tmp_path / "agent_good.key"
    w.good_server_key.write_bytes(good_key)

    # Server leaf — WRONG SPIFFE URI SAN, same trusted chain.
    wrong_pem, wrong_key = _make_leaf(ca_key, ca_cert, cn="agent-leaf", spiffe_uri=WRONG_SPIFFE)
    w.wrong_server_cert = tmp_path / "agent_wrong.crt"
    w.wrong_server_cert.write_bytes(wrong_pem)
    w.wrong_server_key = tmp_path / "agent_wrong.key"
    w.wrong_server_key.write_bytes(wrong_key)

    # Server leaf — NO SAN at all, same trusted chain.
    nosan_pem, nosan_key = _make_leaf(ca_key, ca_cert, cn="agent-leaf", spiffe_uri=None)
    w.nosan_server_cert = tmp_path / "agent_nosan.crt"
    w.nosan_server_cert.write_bytes(nosan_pem)
    w.nosan_server_key = tmp_path / "agent_nosan.key"
    w.nosan_server_key.write_bytes(nosan_key)

    # Server leaf — correct SPIFFE URI SAN, but signed by an UNTRUSTED CA
    # (not in ca_root.crt) — chain verification must fail regardless of SAN.
    untrusted_pem, untrusted_key = _make_leaf(
        other_ca_key, other_ca_cert, cn="agent-leaf", spiffe_uri=GOOD_SPIFFE
    )
    w.untrusted_server_cert = tmp_path / "agent_untrusted.crt"
    w.untrusted_server_cert.write_bytes(untrusted_pem)
    w.untrusted_server_key = tmp_path / "agent_untrusted.key"
    w.untrusted_server_key.write_bytes(untrusted_key)

    return w


def _server_ctx(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — pure function coverage (no sockets)
# ─────────────────────────────────────────────────────────────────────────────


def test_client_ssl_context_verify_spiffe_requires_expected_id(pki_world):
    with pytest.raises(ValueError, match="expected_spiffe_id"):
        client_ssl_context_verify_spiffe("", identity=pki_world.identity)


def test_context_disables_dns_hostname_check_but_requires_chain(pki_world):
    ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # chain verification NEVER disabled


def test_extract_spiffe_uris_multiple_and_none():
    assert _extract_spiffe_uris(None) == []
    cert = {"subjectAltName": (("DNS", "example.com"), ("URI", GOOD_SPIFFE))}
    assert _extract_spiffe_uris(cert) == [GOOD_SPIFFE]


def test_check_spiffe_identity_raises_on_mismatch():
    class _FakePeer:
        def getpeercert(self):
            return {"subjectAltName": (("URI", WRONG_SPIFFE),)}

    with pytest.raises(ssl.SSLCertVerificationError):
        _check_spiffe_identity(_FakePeer(), GOOD_SPIFFE)


def test_check_spiffe_identity_passes_on_match():
    class _FakePeer:
        def getpeercert(self):
            return {"subjectAltName": (("URI", GOOD_SPIFFE),)}

    _check_spiffe_identity(_FakePeer(), GOOD_SPIFFE)  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — real TLS handshake, async transport (httpx.AsyncClient) — the
# actual production code path (internal_httpx_client_verify_spiffe).
# ─────────────────────────────────────────────────────────────────────────────


async def _serve(cert_path: Path, key_path: Path):
    """Start a real TLS server on an ephemeral port. Returns (server, port)."""
    server_ctx = _server_ctx(cert_path, key_path)

    async def handle(reader, writer):
        try:
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_correct_spiffe_san_no_dns_san_is_accepted(pki_world):
    """Requirement 1: a cert with the correct SPIFFE URI SAN (no DNS SAN) is
    ACCEPTED — even though it has NO DNS SAN at all (the exact shape of a
    ring-fenced agent's per-instance Caddy front leaf)."""
    server, port = await _serve(pki_world.good_server_cert, pki_world.good_server_key)
    async with server:
        asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.05)

        ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
        async with httpx.AsyncClient(verify=ctx) as client:
            resp = await client.get(f"https://127.0.0.1:{port}/", timeout=5)
        assert resp.status_code == 200
        server.close()


async def test_wrong_spiffe_san_is_rejected(pki_world):
    """Requirement 2a: a cert with a WRONG SPIFFE id (but chaining correctly
    to the internal CA) is REJECTED."""
    server, port = await _serve(pki_world.wrong_server_cert, pki_world.wrong_server_key)
    async with server:
        asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.05)

        ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
        with pytest.raises(httpx.TransportError):
            async with httpx.AsyncClient(verify=ctx) as client:
                await client.get(f"https://127.0.0.1:{port}/", timeout=5)
        server.close()


async def test_absent_spiffe_san_is_rejected(pki_world):
    """Requirement 2b: a cert with NO SAN at all (absent SPIFFE id) is
    REJECTED — not silently accepted because 'nothing to compare'."""
    server, port = await _serve(pki_world.nosan_server_cert, pki_world.nosan_server_key)
    async with server:
        asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.05)

        ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
        with pytest.raises(httpx.TransportError):
            async with httpx.AsyncClient(verify=ctx) as client:
                await client.get(f"https://127.0.0.1:{port}/", timeout=5)
        server.close()


async def test_untrusted_chain_is_rejected_regardless_of_correct_spiffe(pki_world):
    """Requirement 3: a cert with the CORRECT SPIFFE URI SAN but signed by a
    CA that is NOT the internal CA is REJECTED — chain verification runs
    (and fails) before the SPIFFE check ever gets a chance to run, proving
    cert verification was never disabled to make the SPIFFE check work."""
    server, port = await _serve(
        pki_world.untrusted_server_cert, pki_world.untrusted_server_key
    )
    async with server:
        asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.05)

        ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
        with pytest.raises(httpx.TransportError) as exc_info:
            async with httpx.AsyncClient(verify=ctx) as client:
                await client.get(f"https://127.0.0.1:{port}/", timeout=5)
        # Must be a chain-verification failure, not our SPIFFE mismatch text —
        # proves OpenSSL's own CERT_REQUIRED chain check fired first.
        assert "SPIFFE identity verification failed" not in str(exc_info.value)
        server.close()


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — real TLS handshake, sync transport (httpx.Client) — proves the
# sslsocket_class hook (used by internal_httpx_client_verify_spiffe's sync
# sibling / any future sync caller) fires identically to the async hook.
# ─────────────────────────────────────────────────────────────────────────────


def _serve_sync_once(cert_path: Path, key_path: Path, bindsock: socket.socket) -> None:
    server_ctx = _server_ctx(cert_path, key_path)
    conn, _ = bindsock.accept()
    try:
        tls = server_ctx.wrap_socket(conn, server_side=True)
        try:
            tls.recv(4096)
            tls.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        finally:
            tls.close()
    except OSError:
        pass  # client rejected the handshake before completing — expected for negative cases


def test_sync_transport_correct_spiffe_is_accepted(pki_world):
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind(("127.0.0.1", 0))
    bindsock.listen(1)
    port = bindsock.getsockname()[1]

    t = threading.Thread(
        target=_serve_sync_once,
        args=(pki_world.good_server_cert, pki_world.good_server_key, bindsock),
        daemon=True,
    )
    t.start()

    ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
    with httpx.Client(verify=ctx) as client:
        resp = client.get(f"https://127.0.0.1:{port}/", timeout=5)
    assert resp.status_code == 200
    t.join(timeout=2)
    bindsock.close()


def test_sync_transport_wrong_spiffe_is_rejected(pki_world):
    bindsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsock.bind(("127.0.0.1", 0))
    bindsock.listen(1)
    port = bindsock.getsockname()[1]

    t = threading.Thread(
        target=_serve_sync_once,
        args=(pki_world.wrong_server_cert, pki_world.wrong_server_key, bindsock),
        daemon=True,
    )
    t.start()

    ctx = client_ssl_context_verify_spiffe(GOOD_SPIFFE, identity=pki_world.identity)
    with pytest.raises(httpx.TransportError):
        with httpx.Client(verify=ctx) as client:
            client.get(f"https://127.0.0.1:{port}/", timeout=5)
    t.join(timeout=2)
    bindsock.close()
