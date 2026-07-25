"""
Yashigani internal PKI — two-tier CA (root → intermediate → leaf).

Public surface:
    load_manifest()         — parse service_identities.yaml
    ServiceIdentity         — dataclass describing one service entry
    CertPolicy              — lifetime + mode config
    current_service()       — resolve "who am I" from YASHIGANI_SERVICE_NAME
    internal_httpx_client() — httpx.AsyncClient pre-wired with CA + client cert
    internal_httpx_client_verify_spiffe() — httpx.AsyncClient for ring-fenced
                             agent peers verified by SPIFFE URI SAN (FINDING C)
    server_ssl_context()    — SSLContext for uvicorn / inbound mTLS
    client_ssl_context()    — SSLContext for outbound internal-CA traffic
    client_ssl_context_verify_spiffe() — SSLContext for a peer identified by
                             SPIFFE URI SAN instead of DNS hostname (FINDING C)

The runtime code NEVER generates certs — cert issuance happens only in
:mod:`yashigani.pki.issuer` which is invoked by install.sh and the
admin-API rotation endpoints. Runtime services only LOAD certs.
"""

from yashigani.pki.identity import (
    CertPolicy,
    EndpointAcl,
    ServiceIdentity,
    current_service,
    load_manifest,
    ManifestError,
    TamperError,
)
from yashigani.pki.client import (
    internal_httpx_client,
    internal_httpx_client_verify_spiffe,
    internal_httpx_sync_client,
)
from yashigani.pki.ssl_context import (
    server_ssl_context,
    client_ssl_context,
    client_ssl_context_verify_spiffe,
)

__all__ = [
    "CertPolicy",
    "EndpointAcl",
    "ServiceIdentity",
    "ManifestError",
    "TamperError",
    "current_service",
    "load_manifest",
    "internal_httpx_client",
    "internal_httpx_client_verify_spiffe",
    "internal_httpx_sync_client",
    "server_ssl_context",
    "client_ssl_context",
    "client_ssl_context_verify_spiffe",
]
