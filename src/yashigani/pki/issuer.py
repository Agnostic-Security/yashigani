"""
Yashigani internal PKI issuer — generates root, intermediate, and leaf certs.

Last updated: 2026-05-24T00:00:00+01:00

Invoked by:
  * install.sh bootstrap_internal_pki()  — first-install cert generation
  * install.sh rotate-certs               — leaf rotation
  * install.sh rotate-intermediate         — intermediate + leaf rotation
  * install.sh rotate-root                 — destructive: root + intermediate + leaf
  * /admin/settings/internal-pki API       — operator-initiated rotations

CLI entry point:  python -m yashigani.pki.issuer <command> [flags]

Commands:
  bootstrap      — generate root + intermediate + all leaves (first install)
  rotate-leaves  — regenerate only leaf certs (intermediate stays)
  rotate-intermediate — regenerate intermediate + all leaves (root stays)
  rotate-root    — DESTRUCTIVE: regenerate everything. Requires --confirm.
  mint-leaf      — regenerate a single service's leaf (used on revoked→unrevoked)
  status         — print cert expiry + renewal status for each service

This module is the only place in the codebase that imports heavy
cryptography primitives. Runtime services import only ``identity``,
``ssl_context``, and ``client`` — which use stdlib ``ssl`` + ``hashlib``.

Design rationale — why not Caddy's pki module as the CA generator?
    Caddy's pki builds the CA inside a running container with restricted
    filesystem permissions on the private key. Extracting that key for
    leaf signing requires either running podman exec as root against the
    caddy container, or mounting the caddy_pki volume into a throwaway
    container as root — both complicate install.sh and make rotation
    semantics non-obvious (Caddy regenerates missing material on restart).
    Generating the root with Python cryptography inside install.sh gives
    us explicit control over the entire lifecycle and avoids the
    bootstrap-ordering loop of "Caddy needs to run to produce the CA,
    but other services need the CA to run to reach Caddy."
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import logging
import secrets
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from yashigani.pki.identity import (
    CASource,
    CertPolicy,
    ManifestError,
    ServiceIdentity,
    load_manifest,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_CURVE = ec.SECP256R1()          # P-256 — aligns with the license verifier
_ORG = "Agnostic Security"
_ROOT_CN = "Yashigani Internal Root CA"
_INTERMEDIATE_CN = "Yashigani Internal Intermediate CA"

_BOOTSTRAP_TOKEN_BYTES = 32      # 256-bit
# 0o400 (owner-read-only) is the only mode psycopg2 accepts for a private
# key file: strict check is "0600 or less if owned by current user, or
# 0640 or less if owned by root". 0o444 would have world read access and
# psycopg2 rejects it outright (tripped by sqlalchemy+psycopg2 migration
# step inside the gateway container).
#
# the internal-review concern — that container uid 1001 couldn't read a
# 0o400 file owned by host uid 501 — is resolved by install.sh calling
# `podman unshare chown` on the key files for each non-root service,
# placing them under the user-namespace-mapped uid that matches each
# container's runtime user.
_FILE_MODE_KEY = 0o400
_FILE_MODE_CERT = 0o444
_FILE_MODE_TOKEN = 0o400


@dataclass
class IssuerPaths:
    secrets_dir: Path
    manifest_path: Path

    # Derived
    @property
    def root_cert(self) -> Path: return self.secrets_dir / "ca_root.crt"
    @property
    def root_key(self) -> Path: return self.secrets_dir / "ca_root.key"
    @property
    def intermediate_cert(self) -> Path: return self.secrets_dir / "ca_intermediate.crt"
    @property
    def intermediate_key(self) -> Path: return self.secrets_dir / "ca_intermediate.key"

    def leaf_cert(self, service: str) -> Path:
        return self.secrets_dir / f"{service}_client.crt"

    def leaf_key(self, service: str) -> Path:
        return self.secrets_dir / f"{service}_client.key"

    def bootstrap_token(self, service: str) -> Path:
        return self.secrets_dir / f"{service}_bootstrap_token"

    @property
    def runtime_manifest(self) -> Path:
        """Path to the runtime-writable agent identity manifest.

        The static ``service_identities.yaml`` (committed IaC, self.manifest_path)
        is read-only at runtime. Agent leaf certs are dynamically issued and their
        identities are appended to this separate runtime manifest. The backoffice
        lifespan loader merges both into the live ServiceIdentityManifest object.

        Layout: <secrets_dir>/var/runtime/service_identities.yaml
        Created by install.sh (empty agents: [] stub) on first install.
        Written by mint_agent_leaf() at runtime.
        """
        return self.secrets_dir / "var" / "runtime" / "service_identities.yaml"

    @staticmethod
    def agent_entry_name(tenant_id: str, agent_name: str, instance_id: str = "") -> str:
        """Canonical file/manifest stem for a dynamically-issued agent identity.

        Legacy (no instance): ``agent_<tenant>_<name>``.
        Per-instance (v4.1 Phase 1a, GAP-1): ``agent_<tenant>_<name>_<nhi_id>``
        — two same-named instances get DISTINCT cert/key files instead of
        silently overwriting each other.
        """
        stem = f"agent_{tenant_id}_{agent_name}"
        if instance_id:
            stem = f"{stem}_{instance_id}"
        return stem

    def agent_cert(self, tenant_id: str, agent_name: str, instance_id: str = "") -> Path:
        """Leaf cert path for a dynamically-issued agent identity."""
        return self.secrets_dir / f"{self.agent_entry_name(tenant_id, agent_name, instance_id)}_client.crt"

    def agent_key(self, tenant_id: str, agent_name: str, instance_id: str = "") -> Path:
        """Leaf key path for a dynamically-issued agent identity."""
        return self.secrets_dir / f"{self.agent_entry_name(tenant_id, agent_name, instance_id)}_client.key"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _write_secret(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Existing files may be 0o444 / 0o400 — not writable by owner. Unlink
    # first so rotation can overwrite without a permission error.
    if path.exists():
        try:
            path.chmod(0o600)
        except (PermissionError, FileNotFoundError):  # pragma: no cover
            pass
        path.unlink()
    path.write_bytes(data)
    try:
        path.chmod(mode)
    except PermissionError:  # pragma: no cover
        logger.warning("chmod failed on %s — permission denied", path)
    except FileNotFoundError:  # pragma: no cover
        # Podman rootless + :U bind-mount: os.chmod() (via fchmodat) can
        # return ENOENT on a file that was just written, due to kernel
        # user-namespace inode visibility lag on some aarch64 kernels
        # (observed with Podman 4.9.3 / Ubuntu 24.04 / Linux 6.8 aarch64).
        # The file IS present on the host; this is a spurious ENOENT from
        # the namespace bridge. Log and continue — mode is advisory for the
        # issuer; the _pki_chown_client_keys step applies correct perms
        # on the host side after the container exits.
        logger.warning("chmod ENOENT on %s — Podman rootless namespace lag, continuing", path)


def _gen_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(_CURVE)


def _name(cn: str, extra: Optional[list[x509.NameAttribute]] = None) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if extra:
        attrs.extend(extra)
    return x509.Name(attrs)


def _serial() -> int:
    return int.from_bytes(secrets.token_bytes(16), "big") | 1


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: "CertificateIssuerPrivateKeyTypes | ec.EllipticCurvePrivateKey") -> bytes:
    """Serialise an EC or RSA private key to PKCS#8 PEM (unencrypted)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_key(path: Path) -> CertificateIssuerPrivateKeyTypes:
    """Load a PEM private key. Accepts EC or RSA keys (v2.24.1+ BYO RSA broadening).
    Yashigani-generated intermediates are always EC; BYO intermediates may be RSA."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
        raise RuntimeError(
            f"{path} is not an EC or RSA private key — got {type(key).__name__!r}. "
            "Only EC (P-256 / P-384 / P-521) and RSA (≥ 2048-bit) keys are supported."
        )
    return key  # type: ignore[return-value]


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


# ─────────────────────────────────────────────────────────────────────────────
# BYO-CA helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_byo_intermediate(
    ca_source: "CASource",
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes, Optional[x509.Certificate]]:
    """Load and validate customer-supplied BYO intermediate CA material.

    Returns:
        (intermediate_cert, intermediate_key, root_cert_or_None)

    ``root_cert_or_None`` is the customer root cert when ``ca_source.byo_root_cert_path``
    is provided, otherwise None (in which case the intermediate is used as the trust
    anchor written to ``ca_root.crt`` — valid for short-chain deployments where the
    customer intermediate is self-signed or the root is not provided).

    Validation performed (mirrors ByoCADriver H3/M2/M3):
      - All required paths must exist and be non-empty
      - Intermediate cert must carry basicConstraints CA:TRUE + keyUsage keyCertSign
      - Intermediate cert must be within its validity window (not expired, not future)
      - Intermediate private key must be parseable as an EC or RSA key (v2.24.1+: RSA ≥ 2048
        accepted; EC P-256/P-384/P-521 accepted; other types rejected)
      - Key/cert must form a matching pair (verified via public-key comparison)
      - If root cert provided: root must carry basicConstraints CA:TRUE and intermediate
        must be directly issued by the root (cryptographic chain check)

    Raises RuntimeError on any validation failure.
    """
    # --- Path presence checks ---
    int_cert_path_str = (ca_source.byo_intermediate_cert_path or "").strip()
    int_key_path_str = (ca_source.byo_intermediate_key_path or "").strip()
    if not int_cert_path_str:
        raise RuntimeError(
            "ca_source.byo.intermediate_cert_path is required for byo_intermediate mode "
            "but is missing or empty in the manifest."
        )
    if not int_key_path_str:
        raise RuntimeError(
            "ca_source.byo.intermediate_key_path is required for byo_intermediate mode "
            "but is missing or empty in the manifest."
        )
    int_cert_path = Path(int_cert_path_str)
    int_key_path = Path(int_key_path_str)
    if not int_cert_path.exists():
        raise RuntimeError(
            f"BYO intermediate cert not found at {int_cert_path}. "
            "Check ca_source.byo.intermediate_cert_path in service_identities.yaml."
        )
    if not int_key_path.exists():
        raise RuntimeError(
            f"BYO intermediate key not found at {int_key_path}. "
            "Check ca_source.byo.intermediate_key_path in service_identities.yaml."
        )

    # --- Parse intermediate cert ---
    try:
        int_cert = x509.load_pem_x509_certificate(int_cert_path.read_bytes())
    except Exception as exc:
        raise RuntimeError(
            f"Cannot parse BYO intermediate cert at {int_cert_path}: {exc}"
        ) from exc

    # --- H3: basicConstraints CA:TRUE ---
    try:
        bc_ext = int_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc_ext.value.ca:
            raise RuntimeError(
                f"BYO intermediate cert at {int_cert_path} does not have "
                "basicConstraints CA:TRUE. Supply a CA certificate, not a leaf cert."
            )
    except x509.ExtensionNotFound:
        raise RuntimeError(
            f"BYO intermediate cert at {int_cert_path} is missing the "
            "BasicConstraints extension. A CA certificate must carry basicConstraints CA:TRUE."
        )

    # --- H3: keyUsage keyCertSign ---
    try:
        ku_ext = int_cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku_ext.value.key_cert_sign:
            raise RuntimeError(
                f"BYO intermediate cert at {int_cert_path} does not have "
                "keyUsage keyCertSign. A CA certificate must be permitted to sign certs."
            )
    except x509.ExtensionNotFound:
        raise RuntimeError(
            f"BYO intermediate cert at {int_cert_path} is missing the KeyUsage extension. "
            "A CA certificate must carry keyUsage with at least keyCertSign."
        )

    # --- M2: Validity window ---
    now = _utcnow()
    if now < int_cert.not_valid_before_utc:
        raise RuntimeError(
            f"BYO intermediate cert at {int_cert_path} is not yet valid "
            f"(notBefore={int_cert.not_valid_before_utc.isoformat()}, now={now.isoformat()})."
        )
    if now > int_cert.not_valid_after_utc:
        raise RuntimeError(
            f"BYO intermediate cert at {int_cert_path} is expired "
            f"(notAfter={int_cert.not_valid_after_utc.isoformat()}, now={now.isoformat()}). "
            "Provide a current intermediate certificate."
        )

    # --- Parse intermediate key ---
    try:
        raw_key = serialization.load_pem_private_key(int_key_path.read_bytes(), password=None)
    except Exception as exc:
        raise RuntimeError(
            f"Cannot parse BYO intermediate key at {int_key_path}: {exc}"
        ) from exc
    # v2.24.1 RSA broadening (Iris BYO CA design memo §3 + #20):
    # Accept RSA keys with ≥ 2048-bit modulus in addition to EC keys.
    # EC keys (P-256 / P-384 / P-521) are still preferred for new deployments.
    # RSA acceptance is required for enterprise customers whose org PKI
    # is RSA-based and whose root CA policy prohibits re-issuance of EC intermediates.
    if isinstance(raw_key, ec.EllipticCurvePrivateKey):
        # EC: any SECP curve is accepted (P-256 minimum by default in enterprise PKI).
        int_key: CertificateIssuerPrivateKeyTypes = raw_key
    elif isinstance(raw_key, rsa.RSAPrivateKey):
        # RSA: require ≥ 2048-bit to meet minimum security requirement (NIST SP 800-57).
        key_size = raw_key.key_size
        if key_size < 2048:
            raise RuntimeError(
                f"BYO intermediate RSA key at {int_key_path} has a {key_size}-bit modulus. "
                "A minimum of 2048 bits is required (NIST SP 800-57 / ASVS V6.2.5). "
                "Provide a 2048-bit, 3072-bit, or 4096-bit RSA key."
            )
        int_key = raw_key
    else:
        key_type = type(raw_key).__name__
        raise RuntimeError(
            f"BYO intermediate key at {int_key_path} is a {key_type!r} — "
            "only EC (P-256 / P-384 / P-521) and RSA (≥ 2048-bit) keys are accepted. "
            "Provide an EC or RSA private key in PKCS#8 PEM format."
        )

    # --- Key/cert pair match (public-key comparison) ---
    cert_pub = int_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = int_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_pub != key_pub:
        raise RuntimeError(
            f"BYO intermediate cert at {int_cert_path} and key at {int_key_path} "
            "do not form a matching pair (public key mismatch). "
            "Verify you supplied the correct key for this certificate."
        )

    # --- Optional root cert ---
    root_cert: Optional[x509.Certificate] = None
    root_cert_path_str = (ca_source.byo_root_cert_path or "").strip()
    if root_cert_path_str:
        root_cert_path = Path(root_cert_path_str)
        if not root_cert_path.exists():
            raise RuntimeError(
                f"BYO root cert not found at {root_cert_path}. "
                "Check ca_source.byo.root_cert_path in service_identities.yaml."
            )
        try:
            root_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
        except Exception as exc:
            raise RuntimeError(
                f"Cannot parse BYO root cert at {root_cert_path}: {exc}"
            ) from exc
        # Root must be a CA cert
        try:
            root_bc = root_cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if not root_bc.value.ca:
                raise RuntimeError(
                    f"BYO root cert at {root_cert_path} does not have "
                    "basicConstraints CA:TRUE. Supply a root CA certificate."
                )
        except x509.ExtensionNotFound:
            raise RuntimeError(
                f"BYO root cert at {root_cert_path} is missing the BasicConstraints extension."
            )
        # Cryptographic chain check: intermediate must be directly issued by root
        try:
            int_cert.verify_directly_issued_by(root_cert)
        except Exception as chain_exc:
            raise RuntimeError(
                f"BYO intermediate cert at {int_cert_path} is not directly issued by "
                f"the root cert at {root_cert_path} (cryptographic chain check failed). "
                f"Detail: {chain_exc}"
            ) from chain_exc

    logger.info(
        "internal-pki: BYO intermediate cert loaded from %s "
        "(subject=%s, not_after=%s, root=%s)",
        int_cert_path,
        int_cert.subject.rfc4514_string(),
        int_cert.not_valid_after_utc,
        root_cert_path_str or "none (intermediate used as trust anchor)",
    )
    return int_cert, int_key, root_cert


# ─────────────────────────────────────────────────────────────────────────────
# Root CA
# ─────────────────────────────────────────────────────────────────────────────

def build_root(policy: CertPolicy, lifetime_years: Optional[int] = None) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    lifetime_years = policy.clamp_root(lifetime_years or policy.root_lifetime_years_default)
    key = _gen_keypair()
    now = _utcnow()
    name = _name(_ROOT_CN)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_serial())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365 * lifetime_years))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


# ─────────────────────────────────────────────────────────────────────────────
# Intermediate CA
# ─────────────────────────────────────────────────────────────────────────────

def build_intermediate(
    root_cert: x509.Certificate,
    root_key: ec.EllipticCurvePrivateKey,
    policy: CertPolicy,
    lifetime_days: Optional[int] = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    lifetime_days = policy.clamp_intermediate(
        lifetime_days or policy.intermediate_lifetime_days_default
    )
    key = _gen_keypair()
    now = _utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(_INTERMEDIATE_CN))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(_serial())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=lifetime_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return cert, key


# ─────────────────────────────────────────────────────────────────────────────
# Leaf certs — per-service client certs (also usable as server certs)
# ─────────────────────────────────────────────────────────────────────────────

def build_leaf(
    service: ServiceIdentity,
    intermediate_cert: x509.Certificate,
    intermediate_key: "CertificateIssuerPrivateKeyTypes | ec.EllipticCurvePrivateKey",
    policy: CertPolicy,
    lifetime_days: Optional[int] = None,
    *,
    extra_dns_sans: Optional[list[str]] = None,
    extra_ip_sans: Optional[list[str]] = None,
    include_service_name_dns_san: bool = True,
    binding_extension_value: Optional[bytes] = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Build a leaf cert. Leaf keys are always EC P-256; the intermediate signing
    key may be EC or RSA (v2.24.1+ BYO RSA broadening)."""
    """Build a leaf cert.

    extra_dns_sans / extra_ip_sans — operator-supplied SANs injected for the
    caddy service only (YSG-CERT-SAN-001). Allows demo / system-use installs to
    include the VM hostname + IP in the Caddy server cert so browsers can reach
    the gateway without a separate CA / Let's Encrypt deployment.

    Ignored for non-caddy services (passed as None from rotate_leaves for those).

    include_service_name_dns_san — v4.1 Phase 1a DNS-SAN hygiene: agent/MCP
    instance leaves are SPIFFE-URI-identified; their synthetic service names
    (``agent_<tenant>_<name>_<nhi_id>``) are not valid hostnames and must not
    widen the DNS SAN surface. mint_agent_leaf passes False → the
    ``DNSName(service.name)`` fallback is skipped. ``localhost`` +
    127.0.0.1/::1 are KEPT on every leaf: the Phase 2 Caddy-front binds the
    instance shim on loopback and in-container healthchecks dial
    ``https://localhost`` — that is the only DNS/IP surface an instance leaf
    needs.

    binding_extension_value — v4.1 Phase 1a GAP-2: when set, embedded as a
    NON-critical custom extension (pki/binding.py BINDING_EXTENSION_OID)
    carrying the sha384(image_digest ‖ scope_hash) change-prevention digest.
    Non-critical because Go crypto/x509 (Caddy ``require_and_verify``) rejects
    leaves with unrecognised CRITICAL extensions; enforcement lives at the OPA
    input layer, not TLS path validation (Phase 1b-i decision — binding.py).
    """
    lifetime_days = policy.clamp_leaf(lifetime_days or policy.leaf_lifetime_days_default)
    key = _gen_keypair()
    now = _utcnow()

    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in service.dns_sans]
    if not sans and include_service_name_dns_san:
        sans = [x509.DNSName(service.name)]
    # Always include localhost + loopback so in-container healthchecks and
    # self-connecting clients can verify the cert against their own hostname.
    existing_dns = {n.value for n in sans if isinstance(n, x509.DNSName)}
    for local_name in ("localhost",):
        if local_name not in existing_dns:
            sans.append(x509.DNSName(local_name))
    import ipaddress as _ipaddr
    sans.append(x509.IPAddress(_ipaddr.IPv4Address("127.0.0.1")))
    sans.append(x509.IPAddress(_ipaddr.IPv6Address("::1")))

    # YSG-CERT-SAN-001 — public-access SANs (demo / system-use path).
    # Operator-supplied hostname + IP are added to the Caddy server cert so
    # TLS handshakes from a browser pointed at the VM IP / hostname succeed
    # without a CA-signed cert. Other services receive no extra SANs.
    if extra_dns_sans:
        for dns_san in extra_dns_sans:
            dns_san = dns_san.strip()
            if dns_san and dns_san not in existing_dns:
                sans.append(x509.DNSName(dns_san))
                existing_dns.add(dns_san)
    if extra_ip_sans:
        import ipaddress as _ipaddr2
        existing_ips = {
            str(n.value) for n in sans if isinstance(n, x509.IPAddress)
        }
        for ip_san in extra_ip_sans:
            ip_san = ip_san.strip()
            if not ip_san or ip_san in existing_ips:
                continue
            try:
                # Accept both IPv4 and IPv6.
                addr = _ipaddr2.ip_address(ip_san)
                if isinstance(addr, _ipaddr2.IPv4Address):
                    sans.append(x509.IPAddress(_ipaddr2.IPv4Address(ip_san)))
                else:
                    sans.append(x509.IPAddress(_ipaddr2.IPv6Address(ip_san)))
                existing_ips.add(ip_san)
            except ValueError:
                logger.warning(
                    "YSG-CERT-SAN-001: skipping invalid IP SAN %r for service %s",
                    ip_san, service.name,
                )
    # SPIFFE URI SAN (v2.23.1 — EX-231-08). All DNS + URI SANs live in the
    # SAME SubjectAlternativeName extension — cryptography emits one extension
    # per add_extension() call, so we must assemble the full GeneralName list
    # before the single add_extension(x509.SubjectAlternativeName(sans), ...)
    # call below. Two SAN extensions are illegal per RFC 5280 §4.2.1.6 and
    # would silently break peer validation in strict clients.
    spiffe_id = (service.spiffe_id or "").strip()
    if spiffe_id:
        if not spiffe_id.startswith("spiffe://"):
            raise RuntimeError(
                f"service {service.name!r} has non-SPIFFE URI {spiffe_id!r} — "
                "manifest validation should have caught this"
            )
        sans.append(x509.UniformResourceIdentifier(spiffe_id))

    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(service.name))
        .issuer_name(intermediate_cert.subject)
        .public_key(key.public_key())
        .serial_number(_serial())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                # RFC 5480 §3: key_encipherment MUST be False for EC keys.
                # EC keys use key_agreement for ECDH; key_encipherment is
                # RSA-only (RSA-PKCS1 / RSA-OAEP transport of symmetric keys).
                # Setting it True on EC caused CRL/policy failures in some TLS
                # stacks. Nico finding, 4.0 Phase 0 (RECONCILIATION-20260627.md §10).
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )
    )
    if binding_extension_value is not None:
        # v4.1 Phase 1a GAP-2 — change-prevention binding digest, NON-critical.
        # Encoding contract lives in pki/binding.py (fixed handoff contract).
        # Phase 1b-i: critical=False is LOAD-BEARING — Go crypto/x509 (Caddy
        # require_and_verify) rejects any leaf carrying an unrecognised
        # CRITICAL extension (RFC 5280 §4.2). Change-prevention is enforced
        # at the OPA input layer, not TLS path validation. Empirically proven
        # against Caddy client_auth (see binding.py module docstring).
        from yashigani.pki.binding import BINDING_EXTENSION_OID
        cert = cert.add_extension(
            x509.UnrecognizedExtension(BINDING_EXTENSION_OID, binding_extension_value),
            critical=False,
        )
    signed = cert.sign(intermediate_key, hashes.SHA256())
    return signed, key


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────

def _write_leaf(
    paths: IssuerPaths,
    service: ServiceIdentity,
    leaf_cert: x509.Certificate,
    leaf_key: ec.EllipticCurvePrivateKey,
    intermediate_cert: x509.Certificate,
) -> None:
    """Write leaf cert as leaf||intermediate PEM bundle + key."""
    bundle = _pem_cert(leaf_cert) + _pem_cert(intermediate_cert)
    _write_secret(paths.leaf_cert(service.name), bundle, _FILE_MODE_CERT)
    _write_secret(paths.leaf_key(service.name), _pem_key(leaf_key), _FILE_MODE_KEY)


def _ensure_bootstrap_token(paths: IssuerPaths, service: str) -> str:
    """Write a bootstrap token if one doesn't exist, return SHA-256 hex."""
    tok_path = paths.bootstrap_token(service)
    if tok_path.exists():
        token = tok_path.read_bytes().strip()
    else:
        token = secrets.token_bytes(_BOOTSTRAP_TOKEN_BYTES)
        _write_secret(tok_path, token, _FILE_MODE_TOKEN)
    return hashlib.sha256(token).hexdigest()


def _update_manifest_hashes(
    manifest_path: Path,
    hashes_by_service: dict[str, str],
) -> None:
    """Update bootstrap_token_sha256 fields in service_identities.yaml.

    Uses line-based text edit (not full YAML dump) to preserve comments
    and ordering. The manifest is committed IaC; round-tripping through
    pyyaml drops comments.

    Emits a single INFO audit-trail log line (LU-PKI-A01) with:
      - event_id: per-call UUID4 for correlation
      - pre_sha256: SHA-256 of the manifest text as read from disk
      - post_sha256: SHA-256 of the manifest text as written back to disk
    """
    event_id = str(uuid.uuid4())
    text = manifest_path.read_text()
    manifest_pre_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()

    lines = text.splitlines(keepends=True)
    out: list[str] = []
    current_service: Optional[str] = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("- name:"):
            # Extract name (strip "- name:" and quotes)
            current_service = stripped.split(":", 1)[1].strip().strip('"\'')
        if stripped.startswith("bootstrap_token_sha256:") and current_service:
            h = hashes_by_service.get(current_service)
            if h is not None:
                prefix = line[: len(line) - len(line.lstrip())]
                line = f"{prefix}bootstrap_token_sha256: \"{h}\"\n"
        out.append(line)
        i += 1
    new_text = "".join(out)
    manifest_path.write_text(new_text)
    manifest_post_sha256 = hashlib.sha256(new_text.encode("utf-8")).hexdigest()

    logger.info(
        "internal-pki: manifest write-back complete | event_id=%s | pre_sha256=%s | post_sha256=%s",
        event_id,
        manifest_pre_sha256,
        manifest_post_sha256,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public operations
# ─────────────────────────────────────────────────────────────────────────────

def bootstrap(
    paths: IssuerPaths,
    *,
    root_lifetime_years: Optional[int] = None,
    intermediate_lifetime_days: Optional[int] = None,
    leaf_lifetime_days: Optional[int] = None,
    caddy_extra_dns_sans: Optional[list[str]] = None,
    caddy_extra_ip_sans: Optional[list[str]] = None,
) -> dict[str, str]:
    """First-install: generate root + intermediate + leaves for every non-revoked service.

    Behaviour varies by ca_source.mode in the manifest:

    ``yashigani_generated`` (default):
        Generate Yashigani's own root CA, sign an intermediate, sign all leaf certs.

    ``byo_intermediate`` (v2.24.0+):
        Skip root and intermediate generation.  Load the customer-supplied intermediate
        cert + key (and optionally the customer root cert) from the paths declared in
        ca_source.byo.{intermediate_cert_path, intermediate_key_path, root_cert_path}.
        Validate the BYO material (basicConstraints, keyUsage, expiry, key/cert pair,
        and cryptographic chain to root if root is supplied).  Copy the validated files
        into the canonical secrets-dir locations (ca_root.crt = customer root or
        customer intermediate when root not provided; ca_intermediate.crt = customer
        intermediate).  Then sign leaf certs using the customer intermediate exactly
        as in the yashigani_generated path.

    ``byo_root``:
        Not implemented in v2.24.0.  Raises RuntimeError.  Use ``byo_intermediate``
        instead (the customer provides a sub-CA delegated from their root; the root
        key never touches the Yashigani host).

    ``remote_acme``:
        Existing behaviour (unchanged).

    caddy_extra_dns_sans / caddy_extra_ip_sans — appended to the caddy leaf cert
    SAN only (YSG-CERT-SAN-001). Enables demo / system-use access via VM IP or
    hostname without a CA-signed cert. Other services are unaffected.

    Returns a dict of service_name -> sha256 of the bootstrap token written.
    """
    manifest = load_manifest(str(paths.manifest_path))
    policy = manifest.cert_policy
    ca_source = manifest.ca_source

    # ── Mode: byo_root — not implemented in v2.24.0 ─────────────────────────
    if ca_source.mode == "byo_root":
        raise RuntimeError(
            "ca_source.mode=byo_root is not supported in v2.24.0. "
            "Use byo_intermediate instead: provide a sub-CA cert + key that your "
            "root CA has already signed, and supply the root cert for chain validation. "
            "byo_root (where Yashigani signs its own intermediate under your root) "
            "is deferred to a future release."
        )

    # ── Mode: byo_intermediate ────────────────────────────────────────────────
    if ca_source.mode == "byo_intermediate":
        return _bootstrap_byo_intermediate(
            paths, ca_source, policy, leaf_lifetime_days,
            caddy_extra_dns_sans, caddy_extra_ip_sans,
        )

    # ── Mode: yashigani_generated (default) + remote_acme (pass-through) ─────
    if paths.root_cert.exists() or paths.root_key.exists():
        raise RuntimeError(
            f"Root CA already exists at {paths.root_cert} / {paths.root_key}. "
            "Refusing to overwrite. Use rotate-root --confirm to rotate."
        )

    # 1. Root
    root_cert, root_key = build_root(policy, root_lifetime_years)
    _write_secret(paths.root_cert, _pem_cert(root_cert), _FILE_MODE_CERT)
    _write_secret(paths.root_key, _pem_key(root_key), _FILE_MODE_KEY)
    logger.info("internal-pki: root CA generated, valid until %s", root_cert.not_valid_after_utc)

    # 2. Intermediate
    int_cert, int_key = build_intermediate(root_cert, root_key, policy, intermediate_lifetime_days)
    _write_secret(paths.intermediate_cert, _pem_cert(int_cert), _FILE_MODE_CERT)
    _write_secret(paths.intermediate_key, _pem_key(int_key), _FILE_MODE_KEY)
    logger.info("internal-pki: intermediate CA issued, valid until %s", int_cert.not_valid_after_utc)

    # 3. Leaves + bootstrap tokens
    hashes_by_service: dict[str, str] = {}
    for service in manifest.live_services():
        # YSG-CERT-SAN-001: inject public-access SANs only into the caddy leaf.
        _extra_dns = caddy_extra_dns_sans if service.name == "caddy" else None
        _extra_ip = caddy_extra_ip_sans if service.name == "caddy" else None
        leaf_cert, leaf_key = build_leaf(
            service, int_cert, int_key, policy, leaf_lifetime_days,
            extra_dns_sans=_extra_dns, extra_ip_sans=_extra_ip,
        )
        _write_leaf(paths, service, leaf_cert, leaf_key, int_cert)
        hashes_by_service[service.name] = _ensure_bootstrap_token(paths, service.name)
        logger.info(
            "internal-pki: leaf issued for %s, valid until %s",
            service.name,
            leaf_cert.not_valid_after_utc,
        )

    _update_manifest_hashes(paths.manifest_path, hashes_by_service)
    return hashes_by_service


def _bootstrap_byo_intermediate(
    paths: IssuerPaths,
    ca_source: "CASource",
    policy: CertPolicy,
    leaf_lifetime_days: Optional[int],
    caddy_extra_dns_sans: Optional[list[str]],
    caddy_extra_ip_sans: Optional[list[str]],
) -> dict[str, str]:
    """Inner implementation for bootstrap() when ca_source.mode == 'byo_intermediate'.

    1. Load + validate customer intermediate (and optional root) via _load_byo_intermediate().
    2. Write trust bundle:
       ca_root.crt      = customer root cert (if provided) else customer intermediate cert
       ca_intermediate.crt = customer intermediate cert
       ca_intermediate.key = customer intermediate key
       NOTE: ca_root.key is NOT written — the customer root private key is never stored
             on the Yashigani host.
    3. Issue leaf certs signed by the customer intermediate.
    4. Write bootstrap tokens and update manifest hashes.
    """
    # Guard: refuse to overwrite an existing BYO or generated intermediate.
    # For BYO mode the canonical check is on the intermediate (the root key
    # is never written, so paths.root_key can't be the sentinel).
    if paths.intermediate_cert.exists() or paths.intermediate_key.exists():
        raise RuntimeError(
            f"Intermediate CA already exists at {paths.intermediate_cert} / "
            f"{paths.intermediate_key}. Refusing to overwrite. "
            "Delete the existing intermediate files and re-run bootstrap, "
            "or use rotate-leaves to re-issue leaf certs against the existing intermediate."
        )

    # 1. Load + validate BYO material
    int_cert, int_key, root_cert = _load_byo_intermediate(ca_source)

    # 2. Write trust bundle
    # ca_root.crt = customer root if provided; else customer intermediate (short chain)
    trust_anchor_cert = root_cert if root_cert is not None else int_cert
    _write_secret(paths.root_cert, _pem_cert(trust_anchor_cert), _FILE_MODE_CERT)
    logger.info(
        "internal-pki: BYO trust anchor written to %s (subject=%s)",
        paths.root_cert,
        trust_anchor_cert.subject.rfc4514_string(),
    )

    # ca_intermediate.crt + ca_intermediate.key = customer intermediate material
    _write_secret(paths.intermediate_cert, _pem_cert(int_cert), _FILE_MODE_CERT)
    _write_secret(paths.intermediate_key, _pem_key(int_key), _FILE_MODE_KEY)
    logger.info(
        "internal-pki: BYO intermediate cert + key written to %s / %s",
        paths.intermediate_cert,
        paths.intermediate_key,
    )

    # 3. Leaves + bootstrap tokens
    manifest = load_manifest(str(paths.manifest_path))
    hashes_by_service: dict[str, str] = {}
    for service in manifest.live_services():
        _extra_dns = caddy_extra_dns_sans if service.name == "caddy" else None
        _extra_ip = caddy_extra_ip_sans if service.name == "caddy" else None
        leaf_cert, leaf_key = build_leaf(
            service, int_cert, int_key, policy, leaf_lifetime_days,
            extra_dns_sans=_extra_dns, extra_ip_sans=_extra_ip,
        )
        _write_leaf(paths, service, leaf_cert, leaf_key, int_cert)
        hashes_by_service[service.name] = _ensure_bootstrap_token(paths, service.name)
        logger.info(
            "internal-pki: BYO leaf issued for %s (signed by customer intermediate), "
            "valid until %s",
            service.name,
            leaf_cert.not_valid_after_utc,
        )

    _update_manifest_hashes(paths.manifest_path, hashes_by_service)
    return hashes_by_service


def rotate_leaves(
    paths: IssuerPaths,
    *,
    leaf_lifetime_days: Optional[int] = None,
    only_service: Optional[str] = None,
    caddy_extra_dns_sans: Optional[list[str]] = None,
    caddy_extra_ip_sans: Optional[list[str]] = None,
) -> list[str]:
    """Re-issue leaf certs using the existing intermediate. Returns rotated names.

    caddy_extra_dns_sans / caddy_extra_ip_sans — injected into the caddy leaf cert
    SAN only (YSG-CERT-SAN-001). Enables demo / system-use access via VM IP or
    hostname. Other services are unaffected.
    """
    if not paths.intermediate_cert.exists() or not paths.intermediate_key.exists():
        raise RuntimeError(
            "Intermediate CA missing — run bootstrap or rotate-intermediate first."
        )
    manifest = load_manifest(str(paths.manifest_path))
    int_cert = _load_cert(paths.intermediate_cert)
    int_key = _load_key(paths.intermediate_key)
    rotated: list[str] = []
    hashes_by_service: dict[str, str] = {}
    for service in manifest.live_services():
        if only_service and service.name != only_service:
            continue
        # YSG-CERT-SAN-001: inject public-access SANs only into the caddy leaf.
        _extra_dns = caddy_extra_dns_sans if service.name == "caddy" else None
        _extra_ip = caddy_extra_ip_sans if service.name == "caddy" else None
        leaf_cert, leaf_key = build_leaf(
            service, int_cert, int_key, manifest.cert_policy, leaf_lifetime_days,
            extra_dns_sans=_extra_dns, extra_ip_sans=_extra_ip,
        )
        _write_leaf(paths, service, leaf_cert, leaf_key, int_cert)
        # Ensure bootstrap token exists for this service (idempotent) and capture
        # the hash so we can update the manifest.
        # Compose upgrade path: rotate_leaves() previously discarded the hash and
        # never called _update_manifest_hashes(), leaving stale committed
        # bootstrap_token_sha256 values in the manifest that no longer matched
        # the on-disk token → TamperError at gateway startup.  Fix: collect hashes
        # here and write them back at the end, matching the bootstrap() flow.
        # K8s: _update_manifest_hashes still runs (harmlessly writing into the
        # container's copy of /manifest.yaml) but K8s verification is skipped via
        # _IN_KUBERNETES in ssl_context.py, so the manifset write-back is not load-
        # bearing on that path.
        hashes_by_service[service.name] = _ensure_bootstrap_token(paths, service.name)
        rotated.append(service.name)
        logger.info(
            "internal-pki: rotated leaf for %s, valid until %s",
            service.name,
            leaf_cert.not_valid_after_utc,
        )
    # Write bootstrap_token_sha256 back to the manifest for ALL rotated services.
    # When only_service is set, hashes_by_service contains exactly one entry and
    # only that service's line is touched; other entries are left as-is.
    if hashes_by_service:
        _update_manifest_hashes(paths.manifest_path, hashes_by_service)
    return rotated


def rotate_intermediate(
    paths: IssuerPaths,
    *,
    intermediate_lifetime_days: Optional[int] = None,
    leaf_lifetime_days: Optional[int] = None,
) -> None:
    """Re-issue intermediate under the existing root + reissue every leaf."""
    if not paths.root_cert.exists() or not paths.root_key.exists():
        raise RuntimeError("Root CA missing — run bootstrap first.")
    manifest = load_manifest(str(paths.manifest_path))
    root_cert = _load_cert(paths.root_cert)
    # Yashigani-generated root keys are always EC — the broader return type of
    # _load_key() covers BYO intermediates, but rotate_intermediate only runs
    # when ca_root.key exists (written only in yashigani_generated mode).
    root_key = _load_key(paths.root_key)  # type: ignore[assignment]
    int_cert, int_key = build_intermediate(
        root_cert, root_key, manifest.cert_policy, intermediate_lifetime_days  # type: ignore[arg-type]
    )
    _write_secret(paths.intermediate_cert, _pem_cert(int_cert), _FILE_MODE_CERT)
    _write_secret(paths.intermediate_key, _pem_key(int_key), _FILE_MODE_KEY)
    logger.info(
        "internal-pki: intermediate rotated, valid until %s", int_cert.not_valid_after_utc
    )
    rotate_leaves(paths, leaf_lifetime_days=leaf_lifetime_days)


def rotate_root(
    paths: IssuerPaths,
    *,
    root_lifetime_years: Optional[int] = None,
    intermediate_lifetime_days: Optional[int] = None,
    leaf_lifetime_days: Optional[int] = None,
    confirm: bool = False,
) -> None:
    """DESTRUCTIVE: new root, new intermediate, new leaves, trust-bundle swap."""
    if not confirm:
        raise RuntimeError(
            "rotate-root is destructive and requires confirm=True. "
            "Every service's trust bundle will be replaced; expect a "
            "brief mesh-wide restart window."
        )
    if paths.root_cert.exists():
        paths.root_cert.unlink()
    if paths.root_key.exists():
        paths.root_key.unlink()
    bootstrap(
        paths,
        root_lifetime_years=root_lifetime_years,
        intermediate_lifetime_days=intermediate_lifetime_days,
        leaf_lifetime_days=leaf_lifetime_days,
    )


def _append_agent_identity_to_runtime_manifest(
    paths: IssuerPaths,
    entry_name: str,
    spiffe_id: str,
    cert_not_after_iso: str,
) -> None:
    """Append a new agent identity entry to the runtime manifest (YAML append).

    The runtime manifest lives at paths.runtime_manifest (separate from the
    committed IaC manifest at paths.manifest_path). It is created empty by
    install.sh and never committed to git.

    Format appended (entry_name = IssuerPaths.agent_entry_name(...) — includes
    the ``_<nhi_id>`` instance suffix for per-instance identities, GAP-1):
        - name: agent_<tenant_id>_<agent_name>[_<nhi_id>]
          spiffe_id: spiffe://…/agents/<tenant_id>/<agent_name>[/<nhi_id>]
          dns_sans: []
          purpose: agent-identity
          mtls_capable: true
          revoked: false
          cert_not_after: <ISO datetime>

    Idempotent: if an entry with the same name already exists it is left
    unchanged (the cert file on disk has already been updated by _write_leaf).
    """
    runtime_path = paths.runtime_manifest
    runtime_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing runtime manifest content (may be empty on first call).
    existing_text = runtime_path.read_text() if runtime_path.exists() else "agent_identities: []\n"

    # Idempotency check: don't append if the name already exists.
    if f"name: {entry_name}" in existing_text:
        logger.info(
            "internal-pki: agent identity %r already present in runtime manifest — skipping append",
            entry_name,
        )
        return

    # YAML block to append.  We write raw YAML rather than round-tripping through
    # pyyaml to preserve existing comments and ordering in the file.
    entry_yaml = (
        f"  - name: {entry_name}\n"
        f"    spiffe_id: {spiffe_id}\n"
        f"    dns_sans: []\n"
        f"    purpose: agent-identity\n"
        f"    mtls_capable: true\n"
        f"    revoked: false\n"
        f"    cert_not_after: \"{cert_not_after_iso}\"\n"
    )

    # Replace the `agent_identities: []` stub (first install) with a proper list,
    # or append to an existing agent_identities block.
    if "agent_identities: []" in existing_text:
        new_text = existing_text.replace(
            "agent_identities: []",
            "agent_identities:\n" + entry_yaml,
        )
    else:
        # File already has agent_identities: block — find its end and append there.
        # Simple heuristic: if the file ends with a newline, append directly.
        new_text = existing_text.rstrip("\n") + "\n" + entry_yaml

    _write_secret(runtime_path, new_text.encode("utf-8"), 0o640)
    logger.info(
        "internal-pki: appended agent identity %r to runtime manifest at %s",
        entry_name, runtime_path,
    )



def revoke_agent_identity(
    paths: IssuerPaths,
    tenant_id: str,
    agent_name: str,
    instance_id: str = "",
) -> bool:
    """Mark an agent identity ``revoked: true`` in the runtime manifest (GAP-4).

    Called on NHI deactivate.  The leaf cert file is left on disk (deletion
    requires explicit operator action per repo deletion rules); the manifest
    ``revoked`` flag is the signal the manifest loader / OPA baseline push /
    sidecar binding check consume — a revoked entry must fail the instance
    immediately, without waiting for ``not_after``.

    Returns True when an entry was flipped, False when no matching
    non-revoked entry exists (absent manifest, unknown entry, or already
    revoked).  Never raises on missing files — deactivate must stay usable
    even if PKI state is gone.
    """
    entry_name = IssuerPaths.agent_entry_name(tenant_id, agent_name, instance_id)
    runtime_path = paths.runtime_manifest
    if not runtime_path.exists():
        logger.warning(
            "internal-pki: revoke requested for %r but runtime manifest %s does not exist",
            entry_name, runtime_path,
        )
        return False

    lines = runtime_path.read_text().splitlines(keepends=True)
    in_entry = False
    flipped = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("- name: "):
            in_entry = stripped == f"- name: {entry_name}"
            continue
        if in_entry and stripped == "revoked: false":
            lines[i] = line.replace("revoked: false", "revoked: true")
            flipped = True
            break

    if not flipped:
        logger.warning(
            "internal-pki: revoke found no non-revoked entry %r in runtime manifest",
            entry_name,
        )
        return False

    _write_secret(runtime_path, "".join(lines).encode("utf-8"), 0o640)
    logger.info(
        "internal-pki: agent identity %r marked revoked in runtime manifest", entry_name
    )
    return True


def mint_agent_leaf(
    paths: IssuerPaths,
    tenant_id: str,
    agent_name: str,
    *,
    instance_id: str = "",
    scope_hash: str = "",
    image_digest: str = "",
    leaf_lifetime_days: Optional[int] = None,
    approved_by: str = "",
    approval_audit_jti: str = "",
    audit_writer: Any = None,
) -> str:
    """Issue a per-agent leaf cert and append the identity to the runtime manifest.

    4.0 Phase 0 / §2 of svid-mesh-container-spec.md (RECONCILIATION-20260627.md R10),
    extended by v4.1 Phase 1a (GAP-1/GAP-2):
    Each agent instance gets a SPIFFE ID:
        spiffe://<trust_domain>/agents/<tenant_id>/<agent_name>[/<instance_id>]
    When ``instance_id`` (the registry ``nhi_id``) is supplied, the identity is
    PER-INSTANCE: distinct SPIFFE URI + distinct cert/key files even for two
    same-named agents (GAP-1 — no more collide/overwrite).

    This function:
      1. Generates a new EC P-256 key pair.
      2. Signs a leaf cert against the existing intermediate CA.
         - SPIFFE URI SAN set to the agent SPIFFE ID.
         - key_encipherment=False (RFC 5480, EC keys — Nico finding).
         - No DNS SANs (agents are not externally addressable by hostname).
      3. Writes cert+key to secrets_dir/agent_<tenant_id>_<agent_name>_client.{crt,key}.
      4. Appends the new identity to paths.runtime_manifest.
      5. Emits AgentSvidIssuedEvent on audit_writer (AUDIT-GAP-001 class).

    Returns:
        The SPIFFE ID string of the issued cert (for the admin API response).

    Args:
        paths:               IssuerPaths pointing at the live secrets dir.
        tenant_id:           Tenant/user ID slug (used in SPIFFE URI + file name).
        agent_name:          Agent name slug (e.g. "letta", "langflow").
        instance_id:         Registry nhi_id (``nhi_<12 hex>``) — per-instance
                             identity segment (GAP-1). Empty = legacy shared
                             (tenant, name) identity, unchanged byte-for-byte.
        scope_hash:          Tool-surface hash ``sha384:<hex>`` (binding.py
                             tool_surface_hash). With image_digest, forms the
                             change-prevention binding extension (GAP-2).
        image_digest:        OCI image digest pinned at approve time (may be
                             "" when not yet pinned — recorded as such).
        leaf_lifetime_days:  Override default leaf lifetime from cert policy.
        approved_by:         Admin identity who approved this issuance (for audit).
        approval_audit_jti:  JTI of the admin's approval audit event (for audit chain).
        audit_writer:        Optional audit writer (Any to avoid circular import).
                             CLI callers pass None. Admin API callers pass the live writer.
    """
    from yashigani.identity.trust_domain import agent_spiffe_uri
    from yashigani.pki.binding import binding_digest, encode_binding_extension_value

    manifest = load_manifest(str(paths.manifest_path))
    policy = manifest.cert_policy
    lifetime = leaf_lifetime_days or policy.leaf_lifetime_days_default

    # Load intermediate CA.
    intermediate_cert = _load_cert(paths.intermediate_cert)
    intermediate_key = _load_key(paths.intermediate_key)

    # Build a synthetic ServiceIdentity for this agent.  We do NOT add it to the
    # committed manifest — it goes into the runtime manifest only.
    spiffe_id = agent_spiffe_uri(tenant_id, agent_name, instance_id)
    entry_name = IssuerPaths.agent_entry_name(tenant_id, agent_name, instance_id)
    synthetic_identity = ServiceIdentity(
        name=entry_name,
        dns_sans=(),
        purpose="agent-identity",
        mtls_capable=True,
        bootstrap_token_sha256="",
        revoked=False,
        spiffe_id=spiffe_id,
    )

    # BUG-A (v4.1 Phase 0): args must match build_leaf(service, intermediate_cert,
    # intermediate_key, policy, lifetime_days=...) — see build_leaf def above.
    # GAP-2 change-prevention binding: sha384(image_digest ‖ 0x00 ‖ scope_hash)
    # embedded as a NON-critical extension (contract in pki/binding.py —
    # non-critical so Go crypto/x509 / Caddy require_and_verify accept the
    # leaf; enforcement is at the OPA input layer). Only embedded when a
    # tool-surface baseline exists — a binding over two empty inputs would
    # be a false "nothing was approved" attestation.
    binding_ext = (
        encode_binding_extension_value(image_digest, scope_hash)
        if scope_hash else None
    )

    leaf_cert, leaf_key = build_leaf(
        synthetic_identity,
        intermediate_cert,
        intermediate_key,
        policy,
        lifetime_days=lifetime,
        # DNS-SAN hygiene (Phase 1a): SPIFFE-URI-identified — no synthetic
        # service-name DNS SAN; localhost + loopback retained (see build_leaf).
        include_service_name_dns_san=False,
        binding_extension_value=binding_ext,
    )

    # Write cert+key.  Use agent_cert/agent_key path helpers (separate namespace from
    # regular service leaves to avoid collisions with service names like "gateway").
    cert_path = paths.agent_cert(tenant_id, agent_name, instance_id)
    key_path = paths.agent_key(tenant_id, agent_name, instance_id)
    bundle = _pem_cert(leaf_cert) + _pem_cert(intermediate_cert)
    _write_secret(cert_path, bundle, _FILE_MODE_CERT)
    _write_secret(key_path, _pem_key(leaf_key), _FILE_MODE_KEY)

    cert_not_after = leaf_cert.not_valid_after_utc.isoformat()

    # Append to runtime manifest (entry keyed per-instance — GAP-1).
    _append_agent_identity_to_runtime_manifest(
        paths, entry_name, spiffe_id, cert_not_after,
    )

    logger.info(
        "internal-pki: minted agent leaf | spiffe_id=%s | not_after=%s | approved_by=%r",
        spiffe_id, cert_not_after, approved_by or "cli",
    )

    # Emit audit event (AUDIT-GAP-001: agent SVID issuance must appear in the
    # tamper-evident hash chain, not plain app logs).  audit_writer is None for
    # CLI invocations (no DB / audit chain available); the admin API passes the
    # live writer.
    if audit_writer is not None:
        try:
            # Import lazily to keep issuer.py free of app-layer imports at module load.
            # This module is safe to import in install.sh / CLI context where the audit
            # DB is not initialised.
            from yashigani.audit.schema import AgentSvidIssuedEvent
            event = AgentSvidIssuedEvent(
                agent_name=agent_name,
                tenant_id=tenant_id,
                spiffe_id=spiffe_id,
                cert_not_after=cert_not_after,
                approved_by=approved_by,
                approval_audit_jti=approval_audit_jti,
                # v4.1 Phase 1a GAP-2 — baseline on the tamper-evident chain.
                instance_id=instance_id,
                scope_hash=scope_hash,
                image_digest=image_digest,
                binding_sha384=(binding_digest(image_digest, scope_hash) if scope_hash else ""),
            )
            audit_writer.write(event)
        except Exception as exc:
            # Never let audit failure block cert issuance.  Log at ERROR so it
            # shows in the AUDIT-GAP-001 sweep but does not propagate.
            logger.error(
                "internal-pki: audit write failed for AgentSvidIssuedEvent | "
                "spiffe_id=%s | error=%s",
                spiffe_id, exc,
            )

    return spiffe_id


def status(paths: IssuerPaths) -> list[dict]:
    """Return expiry/renewal status for root, intermediate, and every leaf."""
    out: list[dict] = []
    now = _utcnow()
    manifest = load_manifest(str(paths.manifest_path))
    policy = manifest.cert_policy

    def _entry(name: str, cert_path: Path, lifetime_days: int, kind: str) -> dict:
        if not cert_path.exists():
            return {"name": name, "kind": kind, "status": "missing"}
        cert = _load_cert(cert_path)
        expires_at = cert.not_valid_after_utc
        remaining = (expires_at - now).total_seconds()
        total = lifetime_days * 86400
        frac_remaining = max(0.0, remaining / total) if total else 0.0
        needs_renewal = frac_remaining < policy.renewal_threshold
        return {
            "name": name,
            "kind": kind,
            "status": "ok" if not needs_renewal else "renew",
            "expires_at": expires_at.isoformat(),
            "fraction_remaining": round(frac_remaining, 3),
        }

    out.append(_entry("root", paths.root_cert, policy.root_lifetime_years_default * 365, "root"))
    out.append(_entry("intermediate", paths.intermediate_cert, policy.intermediate_lifetime_days_default, "intermediate"))
    for svc in manifest.live_services():
        out.append(
            _entry(svc.name, paths.leaf_cert(svc.name), policy.leaf_lifetime_days_default, "leaf")
        )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m yashigani.pki.issuer",
        description="Yashigani internal PKI issuer",
    )
    p.add_argument("--secrets-dir", required=True, type=Path)
    p.add_argument("--manifest", required=True, type=Path,
                   help="Path to service_identities.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bootstrap", help="Generate root + intermediate + all leaves")
    b.add_argument("--root-lifetime-years", type=int)
    b.add_argument("--intermediate-lifetime-days", type=int)
    b.add_argument("--leaf-lifetime-days", type=int)
    # YSG-CERT-SAN-001: public-access SANs for demo / system-use deployments.
    b.add_argument(
        "--caddy-extra-dns",
        dest="caddy_extra_dns",
        action="append",
        default=[],
        metavar="HOSTNAME",
        help="Extra DNS SAN to add to the caddy cert (repeatable). Enables demo/system-use access.",
    )
    b.add_argument(
        "--caddy-extra-ip",
        dest="caddy_extra_ip",
        action="append",
        default=[],
        metavar="IP",
        help="Extra IP SAN to add to the caddy cert (repeatable). Enables demo/system-use access.",
    )

    rl = sub.add_parser("rotate-leaves", help="Re-issue all leaf certs")
    rl.add_argument("--leaf-lifetime-days", type=int)
    rl.add_argument("--only", help="Rotate only this service's leaf")
    # YSG-CERT-SAN-001: same extra-SAN flags on rotate-leaves so re-installs
    # and cert-rotation maintenance runs preserve the public-access SANs.
    rl.add_argument(
        "--caddy-extra-dns",
        dest="caddy_extra_dns",
        action="append",
        default=[],
        metavar="HOSTNAME",
        help="Extra DNS SAN to add to the caddy cert on rotation (repeatable).",
    )
    rl.add_argument(
        "--caddy-extra-ip",
        dest="caddy_extra_ip",
        action="append",
        default=[],
        metavar="IP",
        help="Extra IP SAN to add to the caddy cert on rotation (repeatable).",
    )

    ri = sub.add_parser("rotate-intermediate", help="Re-issue intermediate + all leaves")
    ri.add_argument("--intermediate-lifetime-days", type=int)
    ri.add_argument("--leaf-lifetime-days", type=int)

    rr = sub.add_parser("rotate-root", help="DESTRUCTIVE: re-issue root + intermediate + all leaves")
    rr.add_argument("--confirm", action="store_true", required=True)
    rr.add_argument("--root-lifetime-years", type=int)
    rr.add_argument("--intermediate-lifetime-days", type=int)
    rr.add_argument("--leaf-lifetime-days", type=int)

    ml = sub.add_parser("mint-leaf", help="Issue a leaf cert for one service")
    ml.add_argument("service", help="Service name from the manifest")
    ml.add_argument("--leaf-lifetime-days", type=int)

    mal = sub.add_parser(
        "mint-agent-leaf",
        help="Issue a per-agent SVID leaf cert (4.0 Phase 0 / agent-isolation)",
    )
    mal.add_argument("--tenant-id", required=True, help="Tenant/user ID (slug; used in SPIFFE URI + filename)")
    mal.add_argument("--agent-name", required=True, help="Agent name slug (e.g. letta, langflow)")
    mal.add_argument("--leaf-lifetime-days", type=int, help="Override leaf cert lifetime")
    mal.add_argument("--approved-by", default="", help="Admin identity who approved issuance (audit trail)")
    mal.add_argument("--approval-audit-jti", default="", help="JTI of admin approval audit event")

    sub.add_parser("status", help="Print cert expiry status table")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s pki.issuer: %(message)s")
    args = _build_parser().parse_args(argv)
    paths = IssuerPaths(secrets_dir=args.secrets_dir, manifest_path=args.manifest)

    try:
        if args.cmd == "bootstrap":
            hashes = bootstrap(
                paths,
                root_lifetime_years=args.root_lifetime_years,
                intermediate_lifetime_days=args.intermediate_lifetime_days,
                leaf_lifetime_days=args.leaf_lifetime_days,
                caddy_extra_dns_sans=args.caddy_extra_dns or None,
                caddy_extra_ip_sans=args.caddy_extra_ip or None,
            )
            print(f"Bootstrap complete. Issued {len(hashes)} leaf certs.")
        elif args.cmd == "rotate-leaves":
            rotated = rotate_leaves(
                paths,
                leaf_lifetime_days=args.leaf_lifetime_days,
                only_service=args.only,
                caddy_extra_dns_sans=args.caddy_extra_dns or None,
                caddy_extra_ip_sans=args.caddy_extra_ip or None,
            )
            print(f"Rotated {len(rotated)} leaves: {', '.join(rotated)}")
        elif args.cmd == "rotate-intermediate":
            rotate_intermediate(
                paths,
                intermediate_lifetime_days=args.intermediate_lifetime_days,
                leaf_lifetime_days=args.leaf_lifetime_days,
            )
            print("Intermediate + leaves rotated.")
        elif args.cmd == "rotate-root":
            rotate_root(
                paths,
                root_lifetime_years=args.root_lifetime_years,
                intermediate_lifetime_days=args.intermediate_lifetime_days,
                leaf_lifetime_days=args.leaf_lifetime_days,
                confirm=args.confirm,
            )
            print("Root + intermediate + leaves rotated. Mesh-wide restart required.")
        elif args.cmd == "mint-leaf":
            rotated = rotate_leaves(
                paths,
                leaf_lifetime_days=args.leaf_lifetime_days,
                only_service=args.service,
            )
            if not rotated:
                print(f"Service {args.service!r} not found or revoked.", file=sys.stderr)
                return 2
            print(f"Minted leaf for {rotated[0]}.")
        elif args.cmd == "mint-agent-leaf":
            spiffe_id = mint_agent_leaf(
                paths,
                args.tenant_id,
                args.agent_name,
                leaf_lifetime_days=args.leaf_lifetime_days,
                approved_by=args.approved_by,
                approval_audit_jti=args.approval_audit_jti,
                audit_writer=None,  # CLI: no live audit writer
            )
            print(f"Minted agent leaf: {spiffe_id}")
        elif args.cmd == "status":
            for row in status(paths):
                print(row)
        else:  # pragma: no cover
            return 2
    except (ManifestError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
