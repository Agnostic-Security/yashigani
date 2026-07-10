"""
Regression — active CRL revocation channel (4.0, YSG-RISK-058 L3).

Proves the 4.0 addition: when OCSP is unavailable, ``check_revocation``
falls back to the CRL distribution point and:
  * blocks when the leaf serial is in the CRL (REVOKED),
  * blocks when the CRL is stale (STALE),
  * passes when the CRL is fresh and the serial is absent (GOOD),
  * falls through to OCSP ERROR / pin-age logic when all CRL URLs fail.

Also proves per-tenant CRL cache isolation: two different tenant_ids for
the same CRL URL do NOT share a cache entry (item 3 — per-tenant key cache).

Reuses the cert-building helpers from the 3.0 OCSP regression tests.

References:
  YSG-RISK-058 / Laura external-upstream-revocation threat model (PR #35)
  4.0 crypto-hardening item 1 (CRL active channel)
  4.0 crypto-hardening item 3 (per-tenant CRL cache)
"""
from __future__ import annotations

import datetime
import hashlib

import pytest

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

UTC = datetime.timezone.utc


# ---------------------------------------------------------------------------
# Shared cert/CRL builders
# ---------------------------------------------------------------------------


def _mk_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Upstream CA")])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mk_leaf(ca_key, ca_cert, *, crl_url: str = "http://crl.example/c.crl"):
    """Build a leaf cert with a CRL distribution point (no OCSP AIA)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream.example")])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _mk_crl(
    ca_key,
    ca_cert,
    *,
    revoked_serials: list[int] | None = None,
    this_update_offset_hours: float = -1.0,
    next_update_offset_days: float = 1.0,
) -> bytes:
    """Build a CRL DER, optionally revoking specific serial numbers."""
    now = datetime.datetime.now(UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now + datetime.timedelta(hours=this_update_offset_hours))
        .next_update(now + datetime.timedelta(days=next_update_offset_days))
    )
    for sn in (revoked_serials or []):
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(sn)
            .revocation_date(now - datetime.timedelta(hours=2))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(Encoding.DER)


@pytest.fixture(scope="module")
def pki():
    ca_key, ca_cert = _mk_ca()
    _, leaf = _mk_leaf(ca_key, ca_cert)
    leaf_der = leaf.public_bytes(Encoding.DER)
    return {
        "ca_key": ca_key,
        "ca_cert": ca_cert,
        "leaf": leaf,
        "leaf_der": leaf_der,
        "fp": hashlib.sha256(leaf_der).hexdigest(),
        "serial": leaf.serial_number,
    }


# ---------------------------------------------------------------------------
# Import helpers (loaded per-test to pick up fresh module state)
# ---------------------------------------------------------------------------


def _rev():
    """Return the _upstream_revocation module with fresh import."""
    import importlib
    import yashigani.mcp._upstream_revocation as m
    return m


# ===========================================================================
# CRL fallback: OCSP unavailable → CRL is queried
# ===========================================================================


class TestCrlFallback:
    """OCSP unreachable; CRL has a revoked/clean serial."""

    def setup_method(self):
        """Clear the module-level CRL cache so tests don't bleed into each other."""
        from yashigani.mcp._upstream_revocation import _CRL_CACHE, _CRL_CACHE_LOCK
        with _CRL_CACHE_LOCK:
            _CRL_CACHE.clear()

    def _check(self, pki, crl_der: bytes, *, tenant_id: str = "") -> object:
        from yashigani.mcp._upstream_revocation import (
            check_revocation, RevocationConfig,
        )
        cfg = RevocationConfig(
            strict_mode=False,
            tenant_id=tenant_id,
            crl_max_age_seconds=24 * 3600,
        )

        def _ocsp_boom(*a, **k):
            raise OSError("OCSP responder unreachable")

        def _crl_ok(url: str, timeout: float) -> bytes:
            return crl_der

        return check_revocation(
            pki["leaf_der"],
            config=cfg,
            _ocsp_fetch=_ocsp_boom,
            _crl_fetch=_crl_ok,
        )

    def test_crl_revoked_serial_blocks(self, pki):
        """CRL contains the leaf's serial → REVOKED, blocks=True."""
        from yashigani.mcp._upstream_revocation import (
            RevocationStatus, CRL_REVOKED_LABEL,
        )
        crl = _mk_crl(
            pki["ca_key"], pki["ca_cert"],
            revoked_serials=[pki["serial"]],
        )
        res = self._check(pki, crl)
        assert res.status == RevocationStatus.REVOKED
        assert res.blocks is True
        assert res.reason == CRL_REVOKED_LABEL

    def test_crl_clean_serial_passes(self, pki):
        """CRL is fresh and does NOT contain the leaf's serial → GOOD."""
        from yashigani.mcp._upstream_revocation import RevocationStatus
        crl = _mk_crl(
            pki["ca_key"], pki["ca_cert"],
            revoked_serials=[],  # no revocations
        )
        res = self._check(pki, crl)
        assert res.status == RevocationStatus.GOOD
        assert res.blocks is False

    def test_stale_crl_blocks(self, pki):
        """CRL nextUpdate is in the past → STALE, blocks=True."""
        from yashigani.mcp._upstream_revocation import (
            RevocationStatus, CRL_STALE_LABEL,
        )
        # Build CRL with next_update 2 days in the PAST
        stale_crl = _mk_crl(
            pki["ca_key"], pki["ca_cert"],
            revoked_serials=[],
            this_update_offset_hours=-50.0,
            next_update_offset_days=-2.0,   # expired 2 days ago
        )
        res = self._check(pki, stale_crl)
        assert res.status == RevocationStatus.STALE
        assert res.blocks is True
        assert res.reason == CRL_STALE_LABEL

    def test_crl_fetch_failure_falls_through_to_unknown(self, pki):
        """CRL fetch also fails → result is ERROR/UNKNOWN (does not block on its own)."""
        from yashigani.mcp._upstream_revocation import (
            check_revocation, RevocationConfig, RevocationStatus,
        )
        cfg = RevocationConfig(strict_mode=False, tenant_id="")

        def _boom(*a, **k):
            raise OSError("unreachable")

        res = check_revocation(
            pki["leaf_der"],
            config=cfg,
            _ocsp_fetch=_boom,
            _crl_fetch=_boom,
        )
        # Both channels failed: result is UNKNOWN or ERROR, does NOT block.
        assert res.status in (RevocationStatus.UNKNOWN, RevocationStatus.ERROR)
        assert res.blocks is False

    def test_ocsp_revoked_does_not_try_crl(self, pki):
        """OCSP says REVOKED → immediate block; CRL is never called."""
        from yashigani.mcp._upstream_revocation import (
            check_revocation, RevocationConfig, RevocationStatus, REVOKED_LABEL,
        )
        from cryptography.x509.ocsp import (
            OCSPCertStatus, OCSPResponseBuilder, OCSPResponseStatus,
        )
        now = datetime.datetime.now(UTC)
        # Build OCSP REVOKED response
        builder = (
            OCSPResponseBuilder()
            .add_response(
                cert=pki["leaf"], issuer=pki["ca_cert"],
                algorithm=hashes.SHA1(),
                cert_status=OCSPCertStatus.REVOKED,
                this_update=now - datetime.timedelta(minutes=1),
                next_update=now + datetime.timedelta(hours=1),
                revocation_time=now - datetime.timedelta(minutes=5),
                revocation_reason=None,
            )
            .responder_id(x509.ocsp.OCSPResponderEncoding.NAME, pki["ca_cert"])
        )
        ocsp_der = builder.sign(pki["ca_key"], hashes.SHA256()).public_bytes(Encoding.DER)

        crl_called = []

        def _crl_spy(url, timeout):
            crl_called.append(url)
            return _mk_crl(pki["ca_key"], pki["ca_cert"], revoked_serials=[])

        # Patch leaf to have AIA so OCSP is attempted; CRL URL also present.
        # Use a leaf that has BOTH OCSP and CRL extensions.
        from cryptography.x509.oid import AuthorityInformationAccessOID
        leaf_with_aia_der = (
            x509.CertificateBuilder()
            .subject_name(pki["leaf"].subject)
            .issuer_name(pki["ca_cert"].subject)
            .public_key(pki["leaf"].public_key())
            .serial_number(pki["serial"])
            .not_valid_before(datetime.datetime.now(UTC) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example/r"),
                    ),
                ]),
                critical=False,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example/c.crl")],
                        relative_name=None, reasons=None, crl_issuer=None,
                    )
                ]),
                critical=False,
            )
            .sign(pki["ca_key"], hashes.SHA256())
            .public_bytes(Encoding.DER)
        )

        issuer_der = pki["ca_cert"].public_bytes(Encoding.DER)
        cfg = RevocationConfig(strict_mode=False, tenant_id="")
        res = check_revocation(
            leaf_with_aia_der,
            issuer_der=issuer_der,
            config=cfg,
            _ocsp_fetch=lambda *a, **k: ocsp_der,
            _crl_fetch=_crl_spy,
        )
        assert res.status == RevocationStatus.REVOKED
        assert res.blocks is True
        assert res.reason == REVOKED_LABEL
        # CRL must NOT have been called (OCSP gave definitive answer)
        assert crl_called == [], f"CRL was called unexpectedly: {crl_called}"


# ===========================================================================
# Per-tenant CRL cache isolation (item 3)
# ===========================================================================


class TestPerTenantCrlCache:
    """
    Prove that the CRL cache is keyed per tenant_id.

    Two tenants querying the same CRL URL should each get a separate cache
    entry.  We demonstrate this by using a spy that records calls and
    verifying that both tenants trigger a fetch (no cross-tenant cache hit).
    """

    def setup_method(self):
        """Clear the module-level CRL cache between tests."""
        from yashigani.mcp._upstream_revocation import _CRL_CACHE, _CRL_CACHE_LOCK
        with _CRL_CACHE_LOCK:
            _CRL_CACHE.clear()

    def test_different_tenants_have_separate_cache_entries(self, pki):
        from yashigani.mcp._upstream_revocation import (
            check_revocation, RevocationConfig, RevocationStatus, _CRL_CACHE,
        )
        fetch_count = [0]
        crl_der = _mk_crl(pki["ca_key"], pki["ca_cert"], revoked_serials=[])

        def _counting_fetch(url: str, timeout: float) -> bytes:
            fetch_count[0] += 1
            return crl_der

        def _ocsp_boom(*a, **k):
            raise OSError("unreachable")

        cfg_a = RevocationConfig(strict_mode=False, tenant_id="tenant-a")
        cfg_b = RevocationConfig(strict_mode=False, tenant_id="tenant-b")

        res_a = check_revocation(
            pki["leaf_der"], config=cfg_a,
            _ocsp_fetch=_ocsp_boom, _crl_fetch=_counting_fetch,
        )
        res_b = check_revocation(
            pki["leaf_der"], config=cfg_b,
            _ocsp_fetch=_ocsp_boom, _crl_fetch=_counting_fetch,
        )

        # Both should pass (clean serial)
        assert res_a.status == RevocationStatus.GOOD
        assert res_b.status == RevocationStatus.GOOD

        # The fetch was called TWICE: once per tenant (separate cache keys)
        assert fetch_count[0] == 2, (
            f"Expected 2 CRL fetches (one per tenant); got {fetch_count[0]}"
        )

        # Verify separate cache keys exist
        cache_keys = list(_CRL_CACHE.keys())
        tenant_ids_in_cache = {k[0] for k in cache_keys}
        assert "tenant-a" in tenant_ids_in_cache
        assert "tenant-b" in tenant_ids_in_cache

    def test_same_tenant_reuses_cache_entry(self, pki):
        from yashigani.mcp._upstream_revocation import (
            check_revocation, RevocationConfig, RevocationStatus,
        )
        fetch_count = [0]
        crl_der = _mk_crl(pki["ca_key"], pki["ca_cert"], revoked_serials=[])

        def _counting_fetch(url: str, timeout: float) -> bytes:
            fetch_count[0] += 1
            return crl_der

        def _ocsp_boom(*a, **k):
            raise OSError("unreachable")

        cfg = RevocationConfig(strict_mode=False, tenant_id="same-tenant")

        # Call twice for the same tenant
        res1 = check_revocation(
            pki["leaf_der"], config=cfg,
            _ocsp_fetch=_ocsp_boom, _crl_fetch=_counting_fetch,
        )
        res2 = check_revocation(
            pki["leaf_der"], config=cfg,
            _ocsp_fetch=_ocsp_boom, _crl_fetch=_counting_fetch,
        )

        assert res1.status == RevocationStatus.GOOD
        assert res2.status == RevocationStatus.GOOD
        # Only ONE fetch: second call hit the cache
        assert fetch_count[0] == 1, (
            f"Expected 1 CRL fetch (second call should be cached); got {fetch_count[0]}"
        )

    def test_cross_tenant_cache_cannot_poison(self, pki):
        """
        Prove that a 'revoked' CRL cached for tenant-a is NOT returned for
        tenant-b (which uses a 'clean' CRL).  This is the isolation guarantee.
        """
        from yashigani.mcp._upstream_revocation import (
            check_revocation, RevocationConfig, RevocationStatus,
        )
        # CRL for tenant-a: leaf serial is revoked
        crl_der_a = _mk_crl(
            pki["ca_key"], pki["ca_cert"],
            revoked_serials=[pki["serial"]],
        )
        # CRL for tenant-b: leaf serial is clean
        crl_der_b = _mk_crl(
            pki["ca_key"], pki["ca_cert"],
            revoked_serials=[],
        )

        def _ocsp_boom(*a, **k):
            raise OSError("unreachable")

        cfg_a = RevocationConfig(strict_mode=False, tenant_id="poison-a")
        cfg_b = RevocationConfig(strict_mode=False, tenant_id="clean-b")

        # Populate tenant-a cache with a revoked CRL
        res_a = check_revocation(
            pki["leaf_der"], config=cfg_a,
            _ocsp_fetch=_ocsp_boom,
            _crl_fetch=lambda *a, **k: crl_der_a,
        )
        assert res_a.status == RevocationStatus.REVOKED, "Setup: tenant-a should be REVOKED"

        # tenant-b must use its OWN (clean) CRL, not tenant-a's poisoned one
        res_b = check_revocation(
            pki["leaf_der"], config=cfg_b,
            _ocsp_fetch=_ocsp_boom,
            _crl_fetch=lambda *a, **k: crl_der_b,
        )
        assert res_b.status == RevocationStatus.GOOD, (
            f"tenant-b should be GOOD (separate cache), got {res_b.status}"
        )
