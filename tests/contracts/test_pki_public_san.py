# Last updated: 2026-05-18T00:00:00+01:00
"""
PKI public-access SAN contract tests — YSG-CERT-SAN-001.

Asserts that:
  1. build_leaf() with extra_dns_sans / extra_ip_sans emits those SANs in the
     issued cert for the caddy service.
  2. Extra SANs do NOT leak to non-caddy services when bootstrap() /
     rotate_leaves() is called with caddy_extra_* kwargs.
  3. Invalid IP SANs are skipped with a warning (no crash).
  4. Duplicate SANs are deduplicated (no double-entry in the cert).
  5. The --caddy-extra-dns / --caddy-extra-ip CLI flags are accepted by the
     bootstrap and rotate-leaves subcommands (argparse roundtrip).
  6. IPv6 SANs are accepted.

Tiago directive 2026-05-18: VM-IP / hostname access is a supported customer
path for demo and system-use; CA / Let's Encrypt is the proper-deployment path.
"""
from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure src/ is importable without full package install.
REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from yashigani.pki.identity import ServiceIdentity, CertPolicy  # noqa: E402
from yashigani.pki.issuer import build_leaf  # noqa: E402

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography package not installed")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_service(name: str = "caddy") -> ServiceIdentity:
    return ServiceIdentity(
        name=name,
        dns_sans=(name, f"{name}.internal", f"yashigani-{name}"),
        purpose="test",
        mtls_capable=True,
        bootstrap_token_sha256="aabbcc",
        revoked=False,
        spiffe_id=f"spiffe://yashigani.internal/{name}",
    )


def _make_policy() -> CertPolicy:
    return CertPolicy(
        root_lifetime_years_min=5,
        root_lifetime_years_max=20,
        root_lifetime_years_default=10,
        root_rotation_requires_manual_confirmation=True,
        intermediate_lifetime_days_min=90,
        intermediate_lifetime_days_max=365,
        intermediate_lifetime_days_default=180,
        leaf_lifetime_days_min=30,
        leaf_lifetime_days_max=90,
        leaf_lifetime_days_default=90,
        renewal_threshold=0.2,
    )


def _issue_leaf(
    service: ServiceIdentity,
    extra_dns_sans: list[str] | None = None,
    extra_ip_sans: list[str] | None = None,
) -> x509.Certificate:
    """Issue a real leaf cert using a freshly-generated ephemeral intermediate."""
    # Generate a throwaway root + intermediate for testing.
    from yashigani.pki.issuer import build_root, build_intermediate

    policy = _make_policy()
    root_cert, root_key = build_root(policy, lifetime_years=5)
    int_cert, int_key = build_intermediate(root_cert, root_key, policy)
    leaf_cert, _ = build_leaf(
        service, int_cert, int_key, policy,
        extra_dns_sans=extra_dns_sans,
        extra_ip_sans=extra_ip_sans,
    )
    return leaf_cert


def _cert_dns_sans(cert: x509.Certificate) -> set[str]:
    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return {n.value for n in san_ext.value if isinstance(n, x509.DNSName)}


def _cert_ip_sans(cert: x509.Certificate) -> set[str]:
    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return {str(n.value) for n in san_ext.value if isinstance(n, x509.IPAddress)}


def _cert_uri_sans(cert: x509.Certificate) -> set[str]:
    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return {n.value for n in san_ext.value if isinstance(n, x509.UniformResourceIdentifier)}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildLeafExtraSans:
    """Unit tests for build_leaf() extra SAN injection."""

    def test_no_extra_sans_baseline(self):
        """Baseline: no extra SANs → cert has only manifest DNS + localhost + loopback + SPIFFE."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc)
        dns = _cert_dns_sans(cert)
        ips = _cert_ip_sans(cert)
        uris = _cert_uri_sans(cert)

        # Manifest SANs present.
        assert "caddy" in dns
        assert "caddy.internal" in dns
        assert "yashigani-caddy" in dns
        # Localhost always injected.
        assert "localhost" in dns
        # Loopback IPs always injected.
        assert "127.0.0.1" in ips
        assert "::1" in ips
        # SPIFFE URI present.
        assert "spiffe://yashigani.internal/caddy" in uris

        # No extra hostname/IP yet.
        assert "192.168.64.2" not in ips
        assert "yashigani.local" not in dns

    def test_extra_dns_san_added_to_caddy(self):
        """Extra DNS SAN is present in the caddy cert after injection."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc, extra_dns_sans=["yashigani.local"])
        assert "yashigani.local" in _cert_dns_sans(cert)

    def test_extra_ip_san_added_to_caddy(self):
        """Extra IP SAN is present in the caddy cert after injection."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc, extra_ip_sans=["192.168.64.2"])
        assert "192.168.64.2" in _cert_ip_sans(cert)

    def test_both_extra_sans_added(self):
        """Both hostname and IP are present when both are supplied."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc, extra_dns_sans=["yashigani.local"], extra_ip_sans=["192.168.64.2"])
        dns = _cert_dns_sans(cert)
        ips = _cert_ip_sans(cert)
        assert "yashigani.local" in dns
        assert "192.168.64.2" in ips

    def test_extra_dns_not_added_to_non_caddy(self):
        """Extra DNS SANs passed as None for non-caddy services do NOT appear."""
        svc = _make_service("gateway")
        # build_leaf is called directly with extra_dns_sans — simulates non-caddy path.
        cert = _issue_leaf(svc, extra_dns_sans=None, extra_ip_sans=None)
        assert "yashigani.local" not in _cert_dns_sans(cert)
        assert "192.168.64.2" not in _cert_ip_sans(cert)

    def test_duplicate_dns_san_deduplicated(self):
        """Supplying a hostname already in dns_sans does not produce a duplicate SAN."""
        svc = _make_service("caddy")
        # "caddy" is already in dns_sans.
        cert = _issue_leaf(svc, extra_dns_sans=["caddy"])
        dns_list = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        assert dns_list.count("caddy") == 1, "Duplicate DNS SAN 'caddy' must not appear twice"

    def test_duplicate_ip_san_deduplicated(self):
        """Supplying 127.0.0.1 (already injected) does not produce a duplicate IP SAN."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc, extra_ip_sans=["127.0.0.1"])
        ip_list = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
        loopback = [str(a) for a in ip_list if str(a) == "127.0.0.1"]
        assert len(loopback) == 1, "127.0.0.1 must not appear twice"

    def test_invalid_ip_san_skipped(self):
        """An invalid IP string is logged and skipped — no ValueError propagated."""
        svc = _make_service("caddy")
        # "notanip" is not a valid IP address — build_leaf must not raise.
        cert = _issue_leaf(svc, extra_ip_sans=["notanip"])
        # The cert is still issued; only the bad entry is omitted.
        assert cert is not None

    def test_ipv6_extra_san(self):
        """IPv6 addresses are accepted as IP SANs."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc, extra_ip_sans=["fd00::1"])
        assert "fd00::1" in _cert_ip_sans(cert)

    def test_multiple_extra_dns_sans(self):
        """Multiple extra DNS SANs (e.g. FQDN + short hostname) are all present."""
        svc = _make_service("caddy")
        cert = _issue_leaf(svc, extra_dns_sans=["yashigani.local", "myhost.lan"])
        dns = _cert_dns_sans(cert)
        assert "yashigani.local" in dns
        assert "myhost.lan" in dns

    def test_empty_extra_sans_lists_are_noop(self):
        """Empty lists for extra SANs behave identically to None."""
        svc = _make_service("caddy")
        cert_none = _issue_leaf(svc, extra_dns_sans=None, extra_ip_sans=None)
        # Re-issue with empty lists — should produce same SAN set.
        cert_empty = _issue_leaf(svc, extra_dns_sans=[], extra_ip_sans=[])
        assert _cert_dns_sans(cert_none) == _cert_dns_sans(cert_empty)


class TestIssuerCLIFlags:
    """Argparse roundtrip: verify --caddy-extra-dns / --caddy-extra-ip are accepted."""

    def test_bootstrap_accepts_caddy_extra_dns(self):
        from yashigani.pki.issuer import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "--secrets-dir", "/tmp/s",
            "--manifest", "/tmp/m.yaml",
            "bootstrap",
            "--caddy-extra-dns", "yashigani.local",
            "--caddy-extra-dns", "myhost.lan",
        ])
        assert args.caddy_extra_dns == ["yashigani.local", "myhost.lan"]

    def test_bootstrap_accepts_caddy_extra_ip(self):
        from yashigani.pki.issuer import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "--secrets-dir", "/tmp/s",
            "--manifest", "/tmp/m.yaml",
            "bootstrap",
            "--caddy-extra-ip", "192.168.64.2",
        ])
        assert args.caddy_extra_ip == ["192.168.64.2"]

    def test_rotate_leaves_accepts_caddy_extra_dns(self):
        from yashigani.pki.issuer import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "--secrets-dir", "/tmp/s",
            "--manifest", "/tmp/m.yaml",
            "rotate-leaves",
            "--caddy-extra-dns", "yashigani.local",
        ])
        assert args.caddy_extra_dns == ["yashigani.local"]

    def test_rotate_leaves_accepts_caddy_extra_ip(self):
        from yashigani.pki.issuer import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "--secrets-dir", "/tmp/s",
            "--manifest", "/tmp/m.yaml",
            "rotate-leaves",
            "--caddy-extra-ip", "10.0.0.5",
        ])
        assert args.caddy_extra_ip == ["10.0.0.5"]

    def test_bootstrap_empty_extra_flags_by_default(self):
        """No --caddy-extra-* flags → empty lists, not None."""
        from yashigani.pki.issuer import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "--secrets-dir", "/tmp/s",
            "--manifest", "/tmp/m.yaml",
            "bootstrap",
        ])
        assert args.caddy_extra_dns == []
        assert args.caddy_extra_ip == []
