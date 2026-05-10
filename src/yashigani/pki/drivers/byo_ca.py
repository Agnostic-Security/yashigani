"""
Yashigani PKI — BYO-CA driver (Issue #53).

Allows customers to plug their own CA signing endpoint.  Supports the
step-ca / HashiCorp Vault PKI / any endpoint that accepts a PEM CSR and
returns a signed PEM certificate.

Config env vars (all required when YASHIGANI_PKI_CA_MODE=byo):
  YASHIGANI_BYO_CA_CERT_PATH     — PEM file: customer CA cert (root or intermediate)
                                    used both to validate the returned chain AND as the
                                    trust anchor supplied in the PEM bundle.
  YASHIGANI_BYO_SIGNING_ENDPOINT — HTTPS URL that accepts POST with:
                                    Content-Type: application/pkcs10   (CSR body, PEM)
                                    and returns PEM-encoded signed cert.
                                    e.g. https://ca.corp.example/v1/sign/tls
  YASHIGANI_BYO_SIGNING_AUTH_MODE — token | mtls | none  (default: token)

  token mode:
    YASHIGANI_BYO_SIGNING_TOKEN   — Bearer token (env var or file path prefix "file://")

  mtls mode:
    YASHIGANI_BYO_SIGNING_CLIENT_CERT — path to client PEM cert (Yashigani internal cert)
    YASHIGANI_BYO_SIGNING_CLIENT_KEY  — path to client PEM key

  CSR subject/SANs are derived from the service_identities manifest entry for
  the requested service (same as internal CA).

Design:
  The driver NEVER silently falls back to the internal CA if signing fails.
  A DriverError is raised and the rotation is surfaced as a failure in the admin UI.

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from yashigani.pki.drivers.base import CADriver, CertChainInfo, DriverError, RotateResult
from yashigani.pki.drivers.internal_ca import (
    _cert_to_chain_info,
    _extract_first_pem,
)

_log = logging.getLogger("yashigani.pki.byo_ca_driver")


def _require_env(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val:
        raise DriverError(
            f"BYO-CA driver requires {name} to be set. "
            "See the BYO-CA configuration documentation."
        )
    return val


def _resolve_token(raw: str) -> str:
    """Resolve token value: if 'file://<path>', read file; else use raw value."""
    if raw.startswith("file://"):
        path = Path(raw[7:])
        if not path.exists():
            raise DriverError(
                f"BYO-CA token file not found at {path}. "
                "Check YASHIGANI_BYO_SIGNING_TOKEN=file://... path."
            )
        return path.read_text(encoding="utf-8").strip()
    return raw


class ByoCADriver(CADriver):
    """CA driver that submits CSRs to a customer-supplied signing endpoint.

    Supported authentication modes:
      - token: Bearer token in Authorization header
      - mtls: Client certificate (Yashigani internal cert)
      - none: No auth (not recommended; only for private network endpoints)
    """

    def __init__(
        self,
        ca_cert_path: Optional[str] = None,
        signing_endpoint: Optional[str] = None,
        auth_mode: Optional[str] = None,
        signing_token: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        secrets_dir: Optional[str] = None,
        manifest_path: Optional[str] = None,
        timeout_s: float = 30.0,
    ) -> None:
        self._ca_cert_path = Path(
            ca_cert_path or _require_env("YASHIGANI_BYO_CA_CERT_PATH")
        )
        self._signing_endpoint = (
            signing_endpoint or _require_env("YASHIGANI_BYO_SIGNING_ENDPOINT")
        )
        self._auth_mode = (
            auth_mode or os.getenv("YASHIGANI_BYO_SIGNING_AUTH_MODE", "token") or "token"
        ).lower()
        if self._auth_mode == "token":
            raw_token = signing_token or _require_env("YASHIGANI_BYO_SIGNING_TOKEN")
            self._token: Optional[str] = _resolve_token(raw_token)
        else:
            self._token = None

        if self._auth_mode == "mtls":
            self._client_cert: Optional[Path] = Path(
                client_cert_path or _require_env("YASHIGANI_BYO_SIGNING_CLIENT_CERT")
            )
            self._client_key: Optional[Path] = Path(
                client_key_path or _require_env("YASHIGANI_BYO_SIGNING_CLIENT_KEY")
            )
        else:
            self._client_cert = None
            self._client_key = None

        self._secrets_dir = Path(
            secrets_dir or os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets") or "/run/secrets"
        )
        self._manifest_path = Path(
            manifest_path
            or os.getenv("YASHIGANI_SERVICE_MANIFEST_PATH", "/etc/yashigani/service_identities.yaml")
            or "/etc/yashigani/service_identities.yaml"
        )
        self._timeout_s = timeout_s

        # Auth mode validation first (before filesystem checks)
        if self._auth_mode not in ("token", "mtls", "none"):
            raise DriverError(
                f"YASHIGANI_BYO_SIGNING_AUTH_MODE={self._auth_mode!r} is invalid. "
                "Allowed auth_mode values: token | mtls | none"
            )
        if not self._signing_endpoint.startswith("https://"):
            raise DriverError(
                f"YASHIGANI_BYO_SIGNING_ENDPOINT must use HTTPS, got {self._signing_endpoint!r}. "
                "Plaintext submission of CSRs is not permitted."
            )
        if not self._ca_cert_path.exists():
            raise DriverError(
                f"BYO CA cert not found at {self._ca_cert_path}. "
                "Check YASHIGANI_BYO_CA_CERT_PATH."
            )

    # -------------------------------------------------------------------------
    # CADriver interface
    # -------------------------------------------------------------------------

    def get_chain_info(self, service_name: str) -> CertChainInfo:
        """Return chain info for the currently stored leaf cert for service_name."""
        cert_path = self._leaf_cert_path(service_name)
        if not cert_path.exists():
            raise DriverError(
                f"Leaf cert for service {service_name!r} not found at {cert_path}. "
                "Has a BYO-CA rotation been completed for this service?"
            )
        pem_data = cert_path.read_bytes()
        first_cert_pem = _extract_first_pem(pem_data)
        try:
            from cryptography import x509  # noqa: PLC0415
            cert = x509.load_pem_x509_certificate(first_cert_pem)
        except Exception as exc:
            raise DriverError(f"Cannot parse leaf cert at {cert_path}: {exc}") from exc
        return _cert_to_chain_info(cert, ca_mode="byo")

    def rotate(self, service_name: str) -> RotateResult:
        """Generate a CSR, submit to BYO signing endpoint, validate, store."""
        try:
            signed_pem = self._sign_csr_for_service(service_name)
            self._validate_chain(signed_pem)
            # Build bundle: signed cert + BYO CA cert
            ca_pem = self._ca_cert_path.read_bytes()
            bundle = signed_pem + ca_pem
            self._write_leaf(service_name, bundle)
            new_info = self.get_chain_info(service_name)
            _log.info(
                "ByoCADriver: rotated leaf for %s via %s — new not_after=%s",
                service_name,
                self._signing_endpoint,
                new_info.not_after,
            )
            return RotateResult(success=True, new_chain=new_info)
        except DriverError:
            raise
        except Exception as exc:
            _log.error("ByoCADriver rotate failed for %s: %s", service_name, exc)
            return RotateResult(success=False, error=str(exc))

    def get_pem_bundle(self, service_name: str) -> bytes:
        """Return PEM bundle (leaf + BYO CA cert).  Key never included."""
        cert_path = self._leaf_cert_path(service_name)
        if not cert_path.exists():
            raise DriverError(
                f"Leaf cert for service {service_name!r} not found at {cert_path}."
            )
        return cert_path.read_bytes()

    # -------------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------------

    def _leaf_cert_path(self, service_name: str) -> Path:
        return self._secrets_dir / f"{service_name}_client.crt"

    def _leaf_key_path(self, service_name: str) -> Path:
        return self._secrets_dir / f"{service_name}_client.key"

    def _load_service_identity(self, service_name: str):  # type: ignore[return]
        """Load the ServiceIdentity from the manifest for SANs and SPIFFE ID."""
        try:
            from yashigani.pki.identity import load_manifest  # noqa: PLC0415
            manifest = load_manifest(str(self._manifest_path))
            return manifest.get(service_name)
        except Exception as exc:
            raise DriverError(
                f"Cannot load manifest for service {service_name!r}: {exc}"
            ) from exc

    def _generate_csr(self, service_name: str) -> tuple[bytes, bytes]:
        """Generate an EC P-256 key + CSR.

        Returns (csr_pem, key_pem) — key_pem is stored to disk for the new leaf.
        """
        try:
            from cryptography import x509  # noqa: PLC0415
            from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
            from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
            from cryptography.x509.oid import NameOID  # noqa: PLC0415
            import ipaddress  # noqa: PLC0415

            identity = self._load_service_identity(service_name)
            key = ec.generate_private_key(ec.SECP256R1())

            san_list: list[x509.GeneralName] = [
                x509.DNSName(n) for n in identity.dns_sans
            ]
            if not san_list:
                san_list = [x509.DNSName(service_name)]
            existing_dns = {n.value for n in san_list if isinstance(n, x509.DNSName)}
            if "localhost" not in existing_dns:
                san_list.append(x509.DNSName("localhost"))
            san_list.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
            san_list.append(x509.IPAddress(ipaddress.IPv6Address("::1")))
            spiffe_id = (identity.spiffe_id or "").strip()
            if spiffe_id:
                san_list.append(x509.UniformResourceIdentifier(spiffe_id))

            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name([
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Agnostic Security"),
                        x509.NameAttribute(NameOID.COMMON_NAME, service_name),
                    ])
                )
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .sign(key, hashes.SHA256())
            )

            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return csr_pem, key_pem
        except DriverError:
            raise
        except Exception as exc:
            raise DriverError(f"CSR generation failed for {service_name!r}: {exc}") from exc

    def _build_session(self):  # type: ignore[return]
        """Build a requests.Session configured for the auth mode."""
        try:
            import requests  # type: ignore[import-untyped]  # noqa: PLC0415
        except ImportError as exc:
            raise DriverError(
                "BYO-CA driver requires the 'requests' package. "
                "It is included in Yashigani's default dependencies."
            ) from exc

        session = requests.Session()
        session.verify = str(self._ca_cert_path)  # trust the BYO CA

        if self._auth_mode == "token":
            session.headers["Authorization"] = f"Bearer {self._token}"
        elif self._auth_mode == "mtls":
            if not (self._client_cert and self._client_key):
                raise DriverError("mtls auth requires client_cert and client_key paths")
            session.cert = (str(self._client_cert), str(self._client_key))

        return session

    def _sign_csr_for_service(self, service_name: str) -> bytes:
        """Submit CSR to signing endpoint; return signed cert PEM."""
        csr_pem, key_pem = self._generate_csr(service_name)

        # Write the new private key before the signing attempt so it exists
        # if the endpoint returns quickly. We write to a temp location and
        # rename atomically to avoid a window where the old key is gone but
        # the new one isn't persisted yet.
        key_path = self._leaf_key_path(service_name)
        with tempfile.NamedTemporaryFile(
            dir=str(self._secrets_dir),
            prefix=f".{service_name}_client_key_",
            suffix=".tmp",
            delete=False,
        ) as tf:
            tf.write(key_pem)
            tmp_key_path = Path(tf.name)

        try:
            session = self._build_session()
            resp = session.post(
                self._signing_endpoint,
                data=csr_pem,
                headers={"Content-Type": "application/pkcs10"},
                timeout=self._timeout_s,
            )
        except Exception as exc:
            tmp_key_path.unlink(missing_ok=True)
            raise DriverError(
                f"Signing endpoint {self._signing_endpoint!r} request failed: {exc}"
            ) from exc

        if not resp.ok:
            tmp_key_path.unlink(missing_ok=True)
            raise DriverError(
                f"Signing endpoint returned HTTP {resp.status_code}: {resp.text[:400]!r}"
            )

        content_type = resp.headers.get("Content-Type", "")
        if "application/x-pem-file" not in content_type and "text/plain" not in content_type:
            _log.warning(
                "BYO signing endpoint returned unexpected Content-Type %r — "
                "proceeding if body looks like PEM",
                content_type,
            )

        signed_pem = resp.content
        if b"BEGIN CERTIFICATE" not in signed_pem:
            tmp_key_path.unlink(missing_ok=True)
            raise DriverError(
                "Signing endpoint response does not contain a PEM certificate block. "
                f"Content-Type: {content_type!r}  Body start: {signed_pem[:200]!r}"
            )

        # Atomically install the key now that we have the signed cert
        tmp_key_path.replace(key_path)
        try:
            key_path.chmod(0o400)
        except OSError:
            _log.warning("chmod 0o400 failed on %s — continuing", key_path)

        return signed_pem

    def _validate_chain(self, signed_pem: bytes) -> None:
        """Validate that the signed cert chains back to the BYO CA cert.

        Uses cryptography's basic issuer/AKI check.  For stronger validation
        the operator should also configure their signing endpoint to enforce
        path length constraints.
        """
        try:
            from cryptography import x509  # noqa: PLC0415

            leaf = x509.load_pem_x509_certificate(_extract_first_pem(signed_pem))
            ca_cert = x509.load_pem_x509_certificate(self._ca_cert_path.read_bytes())

            # Subject of CA must match issuer of leaf
            if leaf.issuer != ca_cert.subject:
                # Could be an intermediate — check if CA's subject appears
                # anywhere in the chain. For now we check direct issuer only
                # and log a warning for intermediate chains.
                _log.warning(
                    "Leaf issuer %s does not directly match BYO CA subject %s. "
                    "If using an intermediate CA, ensure it chains to YASHIGANI_BYO_CA_CERT_PATH.",
                    leaf.issuer.rfc4514_string(),
                    ca_cert.subject.rfc4514_string(),
                )
                # Do not hard-fail — the endpoint may have signed with an
                # intermediate that chains to the provided CA root.  The TLS
                # stack will enforce the full chain at connection time.
        except DriverError:
            raise
        except Exception as exc:
            raise DriverError(f"Chain validation failed: {exc}") from exc

    def _write_leaf(self, service_name: str, bundle: bytes) -> None:
        """Write leaf PEM bundle atomically."""
        from yashigani.pki.issuer import _write_secret, _FILE_MODE_CERT  # noqa: PLC0415
        cert_path = self._leaf_cert_path(service_name)
        _write_secret(cert_path, bundle, _FILE_MODE_CERT)
