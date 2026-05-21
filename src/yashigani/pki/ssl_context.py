"""
SSL context builders for the Yashigani internal mesh.

Every service that listens on the internal network should build a
:func:`server_ssl_context` via these helpers and pass the resulting
:class:`ssl.SSLContext` to uvicorn/asyncpg/redis-py.

Every outbound internal call should build a :func:`client_ssl_context`.

Both contexts enforce:
  * TLS 1.2 minimum (same floor as the edge TLS policy)
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
from typing import Optional

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
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.load_verify_locations(cafile=str(ca_root))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    logger.info(
        "internal-pki: client SSLContext built for %s (peer verify REQUIRED, root anchor)",
        ident.name,
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
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(ca_root_path))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
