"""
Yashigani internal PKI issuer — generates root, intermediate, and leaf certs.

Last updated: 2026-05-17T09:00:00+01:00

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
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from yashigani.pki.identity import (
    CertPolicy,
    Manifest,
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


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError(f"{path} is not an EC private key")
    return key


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


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
    intermediate_key: ec.EllipticCurvePrivateKey,
    policy: CertPolicy,
    lifetime_days: Optional[int] = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    lifetime_days = policy.clamp_leaf(lifetime_days or policy.leaf_lifetime_days_default)
    key = _gen_keypair()
    now = _utcnow()

    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in service.dns_sans]
    if not sans:
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
                key_encipherment=True,
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
        .sign(intermediate_key, hashes.SHA256())
    )
    return cert, key


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
) -> dict[str, str]:
    """First-install: generate root + intermediate + leaves for every non-revoked service.

    Returns a dict of service_name -> sha256 of the bootstrap token written.
    """
    if paths.root_cert.exists() or paths.root_key.exists():
        raise RuntimeError(
            f"Root CA already exists at {paths.root_cert} / {paths.root_key}. "
            "Refusing to overwrite. Use rotate-root --confirm to rotate."
        )
    manifest = load_manifest(str(paths.manifest_path))
    policy = manifest.cert_policy

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
        leaf_cert, leaf_key = build_leaf(service, int_cert, int_key, policy, leaf_lifetime_days)
        _write_leaf(paths, service, leaf_cert, leaf_key, int_cert)
        hashes_by_service[service.name] = _ensure_bootstrap_token(paths, service.name)
        logger.info(
            "internal-pki: leaf issued for %s, valid until %s",
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
) -> list[str]:
    """Re-issue leaf certs using the existing intermediate. Returns rotated names."""
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
        leaf_cert, leaf_key = build_leaf(
            service, int_cert, int_key, manifest.cert_policy, leaf_lifetime_days
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
    root_key = _load_key(paths.root_key)
    int_cert, int_key = build_intermediate(
        root_cert, root_key, manifest.cert_policy, intermediate_lifetime_days
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

    rl = sub.add_parser("rotate-leaves", help="Re-issue all leaf certs")
    rl.add_argument("--leaf-lifetime-days", type=int)
    rl.add_argument("--only", help="Rotate only this service's leaf")

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
            )
            print(f"Bootstrap complete. Issued {len(hashes)} leaf certs.")
        elif args.cmd == "rotate-leaves":
            rotated = rotate_leaves(
                paths, leaf_lifetime_days=args.leaf_lifetime_days, only_service=args.only
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
