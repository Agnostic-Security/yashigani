"""
SSL context builders for the Yashigani internal mesh.

Every service that listens on the internal network should build a
:func:`server_ssl_context` via these helpers and pass the resulting
:class:`ssl.SSLContext` to uvicorn/asyncpg/redis-py.

Every outbound internal call should build a :func:`client_ssl_context`.

Both contexts enforce:
  * TLS 1.3 minimum (matches the Caddy edge policy; all internal mesh peers —
    Postgres 16, Redis 7.4, pgbouncer 1.25, uvicorn/OpenSSL 3.x — support TLS 1.3).
    NOTE: Python's ssl/OpenSSL negotiates a *classical* KEX even at TLS 1.3
    (no PQC-KEX without the oqs-provider); PQC-hybrid KEX (X25519MLKEM768) is
    terminated at the Caddy edge. Internal east-west PQC-KEX is tracked separately.
  * Root CA is the trust anchor for Python ssl consumers.  Python 3.12 /
    OpenSSL 3.0 does NOT auto-set X509_V_FLAG_PARTIAL_CHAIN on
    SSLContext.load_verify_locations(), so intermediate-only anchors fail
    with "unable to get issuer certificate" on Ubuntu 24.04 aarch64 (gate
    #58a evidence, 2026-04-28).  We therefore use ca_root.crt for all
    Python ssl load_verify_locations() calls (Pattern A for Python ssl).
    Caddy/Go/postgres/pgbouncer remain on Pattern B (partial-chain capable).
  * Server context requires client cert on every handshake
  * Hostname verification ON for clients (matches cert SANs)
  * System roots are never loaded — internal mesh only.

Bootstrap token verification (current_service(verify_token=...)):
  In compose / bare-metal deployments the bootstrap token is written to the
  secrets bind-mount by install.sh and acts as a tamper-detection seal on
  the secrets directory.  In Kubernetes deployments the secrets directory is
  populated from the yashigani-pki-certs K8s Secret (RBAC-controlled) which
  is the trust anchor — the bootstrap token files are not included in the
  Secret because they are generated ephemerally by the PKI Job and do not
  need to outlive the job.  Attempting to verify the token in K8s would
  always raise TamperError.  We detect the K8s runtime by the presence of
  KUBERNETES_SERVICE_HOST (injected by the kubelet into every pod) and skip
  token verification in that context only.

Last updated: 2026-05-17T00:00:00+00:00
"""

from __future__ import annotations

import logging
import os
import ssl
from pathlib import Path
from typing import Any, Optional

from yashigani.pki.identity import ServiceIdentity, current_service

logger = logging.getLogger(__name__)

# Kubernetes injects KUBERNETES_SERVICE_HOST into every pod.  In K8s the
# PKI secrets come from the yashigani-pki-certs Secret (RBAC trust anchor);
# bootstrap token files are not included, so token verification is skipped.
_IN_KUBERNETES: bool = bool(os.environ.get("KUBERNETES_SERVICE_HOST", ""))


def server_ssl_context(identity: Optional[ServiceIdentity] = None) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` for inbound mTLS.

    * Loads this service's cert + private key.
    * Trust anchor: ca_root.crt (Pattern A for Python ssl — OpenSSL 3.0 on
      Ubuntu 24.04 does not support partial-chain without X509_V_FLAG_PARTIAL_CHAIN).
    * Requires every connecting client to present a cert signed by the
      internal CA chain (mutual TLS).
    """
    ident = identity or current_service(verify_token=not _IN_KUBERNETES)
    cert_path, key_path, ca_root = ident.expect_cert_files()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_root))
    ctx.verify_mode = ssl.CERT_REQUIRED
    # We explicitly DO NOT load_default_certs() — system trust roots must
    # not bridge into the internal mesh.
    logger.info(
        "internal-pki: server SSLContext built for %s (client auth REQUIRED, root anchor)",
        ident.name,
    )
    return ctx


def client_ssl_context(identity: Optional[ServiceIdentity] = None) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` for outbound internal mTLS.

    Presents this service's client cert to peers and verifies the peer
    cert chain against ca_root.crt (Pattern A for Python ssl).
    """
    ident = identity or current_service(verify_token=not _IN_KUBERNETES)
    cert_path, key_path, ca_root = ident.expect_cert_files()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_root))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    logger.info(
        "internal-pki: client SSLContext built for %s (peer verify REQUIRED, root anchor)",
        ident.name,
    )
    return ctx


def _extract_spiffe_uris(peer_cert: Optional[dict]) -> list[str]:
    """Return every ``spiffe://`` URI SAN on an ``ssl.getpeercert()`` dict.

    Mirrors ``gateway/spiffe_middleware.py::_extract_spiffe_uri_from_cert``
    and ``mcp/_upstream_pin.py::_get_spiffe_id_from_san`` (duplicated rather
    than imported to avoid a pki -> gateway layering inversion; the shape is
    3 lines and stable — SPIFFE spec ยง2 URI SAN).
    """
    if not peer_cert:
        return []
    return [
        value
        for typ, value in peer_cert.get("subjectAltName", [])
        if typ == "URI" and value.startswith("spiffe://")
    ]


def _check_spiffe_identity(tls_obj: Any, expected_spiffe_id: str) -> None:
    """Post-handshake check: the peer leaf's SPIFFE URI SAN must equal
    ``expected_spiffe_id``. Raises :class:`ssl.SSLCertVerificationError` on
    mismatch/absence — the SAME exception class OpenSSL raises for a DNS
    hostname mismatch, so callers see identical failure semantics.

    Called only from ``do_handshake()`` overrides below, which run this
    AFTER ``super().do_handshake()`` returns without raising — i.e. chain
    verification (CERT_REQUIRED against the loaded CA) has ALREADY
    succeeded. This function is never reached on an unverified chain.
    """
    peer_cert = tls_obj.getpeercert()
    observed = _extract_spiffe_uris(peer_cert)
    if expected_spiffe_id not in observed:
        logger.warning(
            "internal-pki: SPIFFE identity mismatch on ring-fence peer — "
            "expected=%r observed=%r",
            expected_spiffe_id, observed,
        )
        raise ssl.SSLCertVerificationError(
            f"SPIFFE identity verification failed: expected {expected_spiffe_id!r}, "
            f"observed {observed!r} in peer certificate URI SANs"
        )


def client_ssl_context_verify_spiffe(
    expected_spiffe_id: str,
    identity: Optional[ServiceIdentity] = None,
) -> ssl.SSLContext:
    """Build a client :class:`ssl.SSLContext` for a ring-fenced-agent peer
    identified by SPIFFE URI SAN rather than DNS hostname.

    FINDING C (v4.1.2 final onboarding e2e, 2026-07-21): agent per-instance
    Caddy fronts (``manifest/codegen.py::_gen_caddy_snippet_mcp``) present a
    leaf whose ONLY SAN is a SPIFFE URI (``spiffe://<td>/agents/<t>/<s>/<i>``)
    — server-cert DNS SANs on instance leaves are localhost/127.0.0.1 only
    (Phase 1a DNS-SAN hygiene). httpx/OpenSSL's default ``check_hostname``
    only matches DNS/IP SANs, so it rejects this cert even though the chain
    is valid — mesh clients dialling ``https://caddy:<mesh_port>`` MUST
    verify by SPIFFE URI SAN instead (codegen.py docstring, "Tom, Issue 2").

    This function differs from :func:`client_ssl_context` ONLY in the
    identity check performed after the handshake:

      * Chain verification is UNCHANGED — ``verify_mode = CERT_REQUIRED``,
        trust anchor = ``ca_root.crt`` (Pattern A), same as every other
        internal-mesh client context. Certificate verification is NEVER
        disabled.
      * ``check_hostname`` is set to ``False`` (the built-in DNS-hostname
        matcher cannot succeed against a URI-only SAN) — but this is NOT a
        bare relaxation: the compensating control is the mandatory
        post-handshake SPIFFE URI SAN check below, installed via
        ``SSLContext.sslobject_class`` / ``.sslsocket_class`` (documented
        CPython extension points for ``wrap_bio()``/``wrap_socket()``, so
        the check runs for both the async (httpx.AsyncClient, bio-based) and
        sync (httpx.Client, socket-based) transports). A cert that chains
        correctly but carries the wrong (or no) SPIFFE URI SAN is REJECTED
        with :class:`ssl.SSLCertVerificationError` — the same failure class
        a DNS hostname mismatch would raise.

    Presents this service's own client cert (mTLS) exactly as
    :func:`client_ssl_context` does — the ring-fence Caddy front requires
    ``client_auth require_and_verify``.
    """
    if not expected_spiffe_id:
        raise ValueError(
            "client_ssl_context_verify_spiffe: expected_spiffe_id must be a "
            "non-empty spiffe:// URI — refusing to build a context with no "
            "identity to verify (would silently disable hostname checking "
            "with no compensating control)."
        )

    ident = identity or current_service(verify_token=not _IN_KUBERNETES)
    cert_path, key_path, ca_root = ident.expect_cert_files()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_root))
    ctx.check_hostname = False  # compensating control: SPIFFE URI SAN check below
    ctx.verify_mode = ssl.CERT_REQUIRED

    class _SpiffeVerifyingSSLObject(ssl.SSLObject):
        """Async (bio-based) peer — used by httpx.AsyncClient's default
        asyncio transport via SSLContext.wrap_bio()."""

        def do_handshake(self, *args: Any, **kwargs: Any) -> Any:
            result = super().do_handshake(*args, **kwargs)
            _check_spiffe_identity(self, expected_spiffe_id)
            return result

    class _SpiffeVerifyingSSLSocket(ssl.SSLSocket):
        """Sync (socket-based) peer — used by httpx.Client's sync transport
        via SSLContext.wrap_socket()."""

        def do_handshake(self, *args: Any, **kwargs: Any) -> Any:
            result = super().do_handshake(*args, **kwargs)
            _check_spiffe_identity(self, expected_spiffe_id)
            return result

    ctx.sslobject_class = _SpiffeVerifyingSSLObject
    ctx.sslsocket_class = _SpiffeVerifyingSSLSocket

    logger.info(
        "internal-pki: SPIFFE-verifying client SSLContext built for %s "
        "(expected peer=%r, chain verify REQUIRED, root anchor, "
        "hostname-check replaced by URI SAN check)",
        ident.name, expected_spiffe_id,
    )
    return ctx


def ca_trust_only_context(ca_root_path: str | Path) -> ssl.SSLContext:
    """Client context that trusts the internal root CA, no client cert.

    Pattern A for Python ssl: anchor is ca_root.crt, not the intermediate.
    Python 3.12 / OpenSSL 3.0 (Ubuntu 24.04) does not auto-set
    X509_V_FLAG_PARTIAL_CHAIN, so intermediate-only anchors fail.

    Used by components that can't present a client cert but still need to
    verify peers — e.g. the install.sh cert-extract step contacting Caddy
    admin before a client cert exists.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(ca_root_path))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
