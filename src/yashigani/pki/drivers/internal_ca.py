"""
Yashigani PKI — InternalCADriver.

Wraps the existing issuer module (yashigani.pki.issuer) so the admin API
can inspect and rotate certs without duplicating logic.

Config (all resolved from env at construction time):
  YASHIGANI_SECRETS_DIR        — where cert/key files live (default /run/secrets)
  YASHIGANI_SERVICE_MANIFEST_PATH — service_identities.yaml

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from yashigani.pki.drivers.base import CADriver, CertChainInfo, DriverError, RotateResult

_log = logging.getLogger("yashigani.pki.internal_ca_driver")

_DEFAULT_SECRETS_DIR = "/run/secrets"
_DEFAULT_MANIFEST = "/etc/yashigani/service_identities.yaml"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_cert(cert_path: Path):  # type: ignore[return]
    """Load a PEM cert using the cryptography library.  Returns x509.Certificate."""
    try:
        from cryptography import x509  # noqa: PLC0415
        return x509.load_pem_x509_certificate(cert_path.read_bytes())
    except Exception as exc:
        raise DriverError(f"Cannot parse cert at {cert_path}: {exc}") from exc


def _fingerprint(cert) -> str:  # type: ignore[return]
    """SHA-256 fingerprint as lowercase hex string (no colons)."""
    try:
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()
    except Exception as exc:
        raise DriverError(f"Cannot compute fingerprint: {exc}") from exc


def _cert_to_chain_info(cert, ca_mode: str = "internal") -> CertChainInfo:
    """Extract metadata from an x509.Certificate object."""
    try:
        from cryptography import x509 as cx509  # noqa: PLC0415

        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        now = _utcnow()
        total_s = (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds()
        remaining_s = (cert.not_valid_after_utc - now).total_seconds()
        frac = max(0.0, remaining_s / total_s) if total_s > 0 else 0.0
        needs_renewal = frac < 0.33

        dns_sans: list[str] = []
        uri_sans: list[str] = []
        ip_sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, cx509.DNSName):
                    dns_sans.append(name.value)
                elif isinstance(name, cx509.UniformResourceIdentifier):
                    uri_sans.append(name.value)
                elif isinstance(name, cx509.IPAddress):
                    ip_sans.append(str(name.value))
        except cx509.ExtensionNotFound:
            pass

        return CertChainInfo(
            subject_cn=cert.subject.get_attributes_for_oid(cx509.oid.NameOID.COMMON_NAME)[0].value,
            issuer_cn=cert.issuer.get_attributes_for_oid(cx509.oid.NameOID.COMMON_NAME)[0].value,
            serial_hex=format(cert.serial_number, "x"),
            not_before=not_before,
            not_after=not_after,
            fingerprint_sha256=_fingerprint(cert),
            dns_sans=dns_sans,
            uri_sans=uri_sans,
            ip_sans=ip_sans,
            chain_depth=1,
            ca_mode=ca_mode,
            needs_renewal=needs_renewal,
        )
    except DriverError:
        raise
    except Exception as exc:
        raise DriverError(f"Cannot extract cert info: {exc}") from exc


class InternalCADriver(CADriver):
    """CA driver backed by Yashigani's internal two-tier PKI."""

    def __init__(
        self,
        secrets_dir: Optional[str] = None,
        manifest_path: Optional[str] = None,
    ) -> None:
        self._secrets_dir = Path(
            secrets_dir or os.getenv("YASHIGANI_SECRETS_DIR", _DEFAULT_SECRETS_DIR) or _DEFAULT_SECRETS_DIR
        )
        self._manifest_path = Path(
            manifest_path or os.getenv("YASHIGANI_SERVICE_MANIFEST_PATH", _DEFAULT_MANIFEST) or _DEFAULT_MANIFEST
        )

    def _leaf_cert_path(self, service_name: str) -> Path:
        return self._secrets_dir / f"{service_name}_client.crt"

    def get_chain_info(self, service_name: str) -> CertChainInfo:
        cert_path = self._leaf_cert_path(service_name)
        if not cert_path.exists():
            raise DriverError(
                f"Leaf cert for service {service_name!r} not found at {cert_path}. "
                "Has install.sh bootstrap_internal_pki() been run?"
            )
        # The leaf cert file is a PEM bundle: leaf + intermediate.
        # Load just the first PEM block (the leaf).
        pem_data = cert_path.read_bytes()
        first_cert_pem = _extract_first_pem(pem_data)
        try:
            from cryptography import x509  # noqa: PLC0415
            cert = x509.load_pem_x509_certificate(first_cert_pem)
        except Exception as exc:
            raise DriverError(f"Cannot parse leaf cert at {cert_path}: {exc}") from exc
        info = _cert_to_chain_info(cert, ca_mode="internal")
        return info

    def rotate(self, service_name: str) -> RotateResult:
        """Re-issue leaf cert for service_name using the existing intermediate."""
        try:
            from yashigani.pki.issuer import IssuerPaths, rotate_leaves  # noqa: PLC0415

            paths = IssuerPaths(
                secrets_dir=self._secrets_dir,
                manifest_path=self._manifest_path,
            )
            rotated = rotate_leaves(paths, only_service=service_name)
            if not rotated:
                return RotateResult(
                    success=False,
                    error=f"Service {service_name!r} not found in manifest or is revoked.",
                )
            new_info = self.get_chain_info(service_name)
            _log.info(
                "InternalCADriver: rotated leaf for %s — new not_after=%s",
                service_name,
                new_info.not_after,
            )
            return RotateResult(success=True, new_chain=new_info)
        except DriverError:
            raise
        except Exception as exc:
            _log.error("InternalCADriver rotate failed for %s: %s", service_name, exc)
            return RotateResult(success=False, error=str(exc))

    def get_pem_bundle(self, service_name: str) -> bytes:
        """Return the PEM bundle (leaf + intermediate).  Never returns the key."""
        cert_path = self._leaf_cert_path(service_name)
        if not cert_path.exists():
            raise DriverError(
                f"Leaf cert for service {service_name!r} not found at {cert_path}."
            )
        # The bundle file contains: leaf PEM + intermediate PEM.
        # The private key is a separate file — never read here.
        return cert_path.read_bytes()


def _extract_first_pem(pem_data: bytes) -> bytes:
    """Extract the first PEM block from a potentially multi-cert PEM bundle."""
    lines: list[bytes] = []
    in_block = False
    for line in pem_data.splitlines(keepends=True):
        if b"BEGIN CERTIFICATE" in line:
            in_block = True
        if in_block:
            lines.append(line)
        if b"END CERTIFICATE" in line and in_block:
            break
    if not lines:
        raise DriverError("No PEM certificate block found in the cert file.")
    return b"".join(lines)
